#include "Dc.h"
#include "BarePool.h"
#include "BufferOp.hpp"
#include "Clock.h"
#include "Crypto.h"
#include "Math.h"
#include "Pool.h"
#include "Queue.h"
#include "Rng.h"
#include "Sctp.h"
#include "Sdp.h"
#include "Stun.h"
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string.h>

struct Dc {
  BarePool *bp;
  double time;
  double dt;
  char host[256];
  uint16_t port;
  Queue *pendingEvents;
  int32_t maxClients;
  int32_t numClients;

  Pool *clientPool;
  Client **clients;
  ssl_ctx_st *sslCtx;

  char certFingerprint[96];

  char errBuf[512];
  void *userData;
  ErrorFn errorCallback;
  WriteFn writeUdpData;
};

const double kMaxClientTtl = 8.0;
const double heartbeatInterval = 4.0;
const int kDefaultMTU = 1400;

static void DefaultErrorCallback(const char *, void *) {}
static void WriteNothing(const uint8_t *, size_t, const Client *, void *) {}

enum DataChannelMessageType { DCMessage_Ack = 0x02, DCMessage_Open = 0x03 };

enum DataChanProtoIdentifier {
  DCProto_Control = 50,
  DCProto_String = 51,
  DCProto_Binary = 53,
  DCProto_EmptyString = 56,
  DCProto_EmptyBinary = 57
};

struct DataChannelPacket {
  uint8_t messageType;

  union {
    struct {
      uint8_t channelType;
      uint16_t priority;
      uint32_t reliability;
    } open;
  } as;
};

enum ClientState {
  Client_Dead,
  Client_WaitingRemoval,
  Client_DTLSHandshake,
  Client_SCTPEstablished,
  Client_DataChannelOpen
};

static int32_t ParseDataChannelControlPacket(const uint8_t *buf, size_t len,
                                             DataChannelPacket *packet) {
  ReadScalarSwapped(buf, &packet->messageType);
  return 0;
}

void ReportError(Dc *dc, const char *description) {
  dc->errorCallback(description, dc->userData);
}

struct Client {
  StunUserIdentifier serverUser;
  StunUserIdentifier serverPassword;
  StunUserIdentifier remoteUser;
  StunUserIdentifier remoteUserPassword;
  Address address;
  ClientState state;
  uint16_t localSctpPort;
  uint16_t remoteSctpPort;
  uint32_t sctpVerificationTag;
  uint32_t remoteTsn;
  uint32_t tsn;
  double ttl;
  double nextHeartbeat;

  SSL *ssl;
  BIO *inBio;
  BIO *outBio;

  void *user;
};

void ClientSetUserData(Client *client, void *user) { client->user = user; }

void *ClientGetUserData(const Client *client) { return client->user; }

static void ClientFinish(Client *client) {
  SSL_free(client->ssl);
  client->ssl = NULL;
  client->inBio = NULL;
  client->outBio = NULL;
  client->state = Client_Dead;
}

static void ClientStart(const Dc *dc, Client *client) {
  client->state = Client_DTLSHandshake;
  client->remoteSctpPort = 0;
  client->sctpVerificationTag = 0;
  client->remoteTsn = 0;
  client->tsn = 1;
  client->ttl = kMaxClientTtl;
  client->nextHeartbeat = heartbeatInterval;
  client->user = NULL;

  client->ssl = SSL_new(dc->sslCtx);

  client->inBio = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(client->inBio, -1);
  client->outBio = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(client->outBio, -1);
  SSL_set_bio(client->ssl, client->inBio, client->outBio);
  SSL_set_options(client->ssl, SSL_OP_SINGLE_ECDH_USE);
  SSL_set_options(client->ssl, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
  SSL_set_tmp_ecdh(client->ssl, EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  SSL_set_accept_state(client->ssl);
  SSL_set_mtu(client->ssl, kDefaultMTU);
}

static void SendSctp(const Dc *dc, Client *client, const SctpPacket *packet,
                     const SctpChunk *chunks, int32_t numChunks);

static Client *NewClient(Dc *dc) {
  Client *client = (Client *)PoolAcquire(dc->clientPool);

  if (client) {
    memset(client, 0, sizeof(Client));
    ClientStart(dc, client);
    dc->clients[dc->numClients++] = client;
    return client;
  }

  return nullptr;
}

static void PushEvent(Dc *dc, Event evt) { QueuePush(dc->pendingEvents, &evt); }

static void SendSctpShutdown(Dc *dc, Client *client) {
  SctpPacket response;
  response.sourcePort = client->localSctpPort;
  response.destionationPort = client->remoteSctpPort;
  response.verificationTag = client->sctpVerificationTag;

  SctpChunk rc;
  rc.type = Sctp_Shutdown;
  rc.flags = 0;
  rc.length = SctpChunkLength(sizeof(rc.as.shutdown.cumulativeTsnAck));
  rc.as.shutdown.cumulativeTsnAck = client->remoteTsn;

  SendSctp(dc, client, &response, &rc, 1);
}

void RemoveClient(Dc *dc, Client *client) {
  for (int32_t i = 0; i < dc->numClients; i++) {
    if (dc->clients[i] == client) {
      SendSctpShutdown(dc, client);
      ClientFinish(client);
      PoolRelease(dc->clientPool, client);
      dc->clients[i] = dc->clients[dc->numClients - 1];
      dc->numClients--;
      return;
    }
  }
}

static Client *FindClient(Dc *dc, const Address *address) {
  for (int32_t i = 0; i < dc->numClients; i++) {
    Client *client = dc->clients[i];
    if (client->address.host == address->host &&
        client->address.port == address->port) {
      return client;
    }
  }

  return NULL;
}

static Client *FindClientByCreds(Dc *dc, const StunUserIdentifier *svUser,
                                 const StunUserIdentifier *clUser) {
  for (int32_t i = 0; i < dc->numClients; i++) {
    Client *client = dc->clients[i];
    if (StunUserIdentifierEqual(&client->serverUser, svUser) &&
        StunUserIdentifierEqual(&client->remoteUser, clUser)) {
      return client;
    }
  }

  return NULL;
}

static void ClientSendPendingDTLS(const Dc *dc, Client *client) {
  uint8_t sendBuffer[4096];

  while (BIO_ctrl_pending(client->outBio) > 0) {
    int bytes = BIO_read(client->outBio, sendBuffer, sizeof(sendBuffer));
    if (bytes > 0) {
      dc->writeUdpData(sendBuffer, bytes, client, dc->userData);
    }
  }
}

static void TLSSend(const Dc *dc, Client *client, const void *data,
                    int32_t length) {
  if (client->state < Client_DTLSHandshake ||
      !SSL_is_init_finished(client->ssl)) {
    return;
  }

  SSL_write(client->ssl, data, length);
  ClientSendPendingDTLS(dc, client);
}

static void SendSctp(const Dc *dc, Client *client, const SctpPacket *packet,
                     const SctpChunk *chunks, int32_t numChunks) {
  uint8_t outBuffer[4096];
  memset(outBuffer, 0, sizeof(outBuffer));
  size_t bytesWritten = SerializeSctpPacket(packet, chunks, numChunks,
                                            outBuffer, sizeof(outBuffer));
  TLSSend(dc, client, outBuffer, bytesWritten);
}

static void HandleSctp(Dc *dc, Client *client, const uint8_t *buf,
                       int32_t len) {
  const size_t maxChunks = 8;
  SctpChunk chunks[maxChunks];
  SctpPacket sctpPacket;
  size_t nChunk = 0;

  if (!ParseSctpPacket(buf, len, &sctpPacket, chunks, maxChunks, &nChunk)) {
    return;
  }

  for (size_t n = 0; n < nChunk; n++) {
    SctpChunk *chunk = &chunks[n];
    if (chunk->type == Sctp_Data) {
      auto *dataChunk = &chunk->as.data;
      const uint8_t *userDataBegin = dataChunk->userData;
      const int32_t userDataLength = dataChunk->userDataLength;

      client->remoteTsn = Max(chunk->as.data.tsn, client->remoteTsn);
      client->ttl = kMaxClientTtl;

      if (dataChunk->protoId == DCProto_Control) {
        DataChannelPacket packet;
        ParseDataChannelControlPacket(userDataBegin, userDataLength, &packet);
        if (packet.messageType == DCMessage_Open) {
          client->remoteSctpPort = sctpPacket.sourcePort;
          uint8_t outType = DCMessage_Ack;
          SctpPacket response;
          response.sourcePort = sctpPacket.destionationPort;
          response.destionationPort = sctpPacket.sourcePort;
          response.verificationTag = client->sctpVerificationTag;

          SctpChunk rc;
          rc.type = Sctp_Data;
          rc.flags = kSctpFlagCompleteUnreliable;
          rc.length = SctpDataChunkLength(1);

          auto *chunkData = &rc.as.data;
          chunkData->tsn = client->tsn++;
          chunkData->streamId = chunk->as.data.streamId;
          chunkData->streamSeq = 0;
          chunkData->protoId = DCProto_Control;
          chunkData->userData = &outType;
          chunkData->userDataLength = 1;

          if (client->state != Client_DataChannelOpen) {
            client->state = Client_DataChannelOpen;
            Event event;
            event.type = Event_ClientJoin;
            event.client = client;
            PushEvent(dc, event);
          }

          SendSctp(dc, client, &response, &rc, 1);
        }
      } else if (dataChunk->protoId == DCProto_String) {
        Event evt;
        evt.type = Event_TextData;
        evt.client = client;
        evt.data = dataChunk->userData;
        evt.length = dataChunk->userDataLength;
        PushEvent(dc, evt);
      } else if (dataChunk->protoId == DCProto_Binary) {
        Event evt;
        evt.type = Event_BinaryData;
        evt.client = client;
        evt.data = dataChunk->userData;
        evt.length = dataChunk->userDataLength;
        PushEvent(dc, evt);
      }

      SctpPacket sack;
      sack.sourcePort = sctpPacket.destionationPort;
      sack.destionationPort = sctpPacket.sourcePort;
      sack.verificationTag = client->sctpVerificationTag;

      SctpChunk rc;
      rc.type = Sctp_Sack;
      rc.flags = 0;
      rc.length = SctpChunkLength(12);
      rc.as.sack.cumulativeTsnAck = client->remoteTsn;
      rc.as.sack.advRecvWindow = kSctpDefaultBufferSpace;
      rc.as.sack.numGapAckBlocks = 0;
      rc.as.sack.numDupTsn = 0;

      SendSctp(dc, client, &sack, &rc, 1);
    } else if (chunk->type == Sctp_Init) {
      SctpPacket response;
      response.sourcePort = sctpPacket.destionationPort;
      response.destionationPort = sctpPacket.sourcePort;
      response.verificationTag = chunk->as.init.initiateTag;
      client->sctpVerificationTag = response.verificationTag;
      client->remoteTsn = chunk->as.init.initialTsn - 1;

      SctpChunk rc;
      rc.type = Sctp_InitAck;
      rc.flags = 0;
      rc.length = kSctpMinInitAckLength;

      rc.as.init.initiateTag = RandomU32();
      rc.as.init.windowCredit = kSctpDefaultBufferSpace;
      rc.as.init.numOutboundStreams = chunk->as.init.numInboundStreams;
      rc.as.init.numInboundStreams = chunk->as.init.numOutboundStreams;
      rc.as.init.initialTsn = client->tsn;

      SendSctp(dc, client, &response, &rc, 1);
      break;
    } else if (chunk->type == Sctp_CookieEcho) {
      if (client->state < Client_SCTPEstablished) {
        client->state = Client_SCTPEstablished;
      }
      SctpPacket response;
      response.sourcePort = sctpPacket.destionationPort;
      response.destionationPort = sctpPacket.sourcePort;
      response.verificationTag = client->sctpVerificationTag;

      SctpChunk rc;
      rc.type = Sctp_CookieAck;
      rc.flags = 0;
      rc.length = SctpChunkLength(0);

      SendSctp(dc, client, &response, &rc, 1);
    } else if (chunk->type == Sctp_Heartbeat) {
      SctpPacket response;
      response.sourcePort = sctpPacket.destionationPort;
      response.destionationPort = sctpPacket.sourcePort;
      response.verificationTag = client->sctpVerificationTag;

      SctpChunk rc;
      rc.type = Sctp_HeartbeatAck;
      rc.flags = 0;
      rc.length = chunk->length;
      rc.as.heartbeat.heartbeatInfoLen = chunk->as.heartbeat.heartbeatInfoLen;
      rc.as.heartbeat.heartbeatInfo = chunk->as.heartbeat.heartbeatInfo;

      client->ttl = kMaxClientTtl;

      SendSctp(dc, client, &response, &rc, 1);
    } else if (chunk->type == Sctp_HeartbeatAck) {
      client->ttl = kMaxClientTtl;
    } else if (chunk->type == Sctp_Abort) {
      client->state = Client_WaitingRemoval;
      return;
    } else if (chunk->type == Sctp_Sack) {
      auto *sack = &chunk->as.sack;
      if (sack->numGapAckBlocks > 0) {
        SctpPacket fwdResponse;
        fwdResponse.sourcePort = sctpPacket.destionationPort;
        fwdResponse.destionationPort = sctpPacket.sourcePort;
        fwdResponse.verificationTag = client->sctpVerificationTag;

        SctpChunk fwdTsnChunk;
        fwdTsnChunk.type = SctpChunk_ForwardTsn;
        fwdTsnChunk.flags = 0;
        fwdTsnChunk.length = SctpChunkLength(4);
        fwdTsnChunk.as.forwardTsn.newCumulativeTsn = client->tsn;
        SendSctp(dc, client, &fwdResponse, &fwdTsnChunk, 1);
      }
    }
  }
}

static void ReceiveDTLSPacket(Dc *dc, const uint8_t *data, size_t length,
                              const Address *address) {
  Client *client = FindClient(dc, address);
  if (!client) {
    return;
  }

  BIO_write(client->inBio, data, length);

  if (!SSL_is_init_finished(client->ssl)) {
    int r = SSL_do_handshake(client->ssl);

    if (r <= 0) {
      r = SSL_get_error(client->ssl, r);
      if (SSL_ERROR_WANT_READ == r) {
        ClientSendPendingDTLS(dc, client);
      } else if (SSL_ERROR_NONE != r) {
        char *error = ERR_error_string(r, NULL);
        if (error) {
          ReportError(dc, error);
        }
      }
    }
  } else {
    ClientSendPendingDTLS(dc, client);

    while (BIO_ctrl_pending(client->inBio) > 0) {
      uint8_t receiveBuffer[8092];
      int bytes = SSL_read(client->ssl, receiveBuffer, sizeof(receiveBuffer));

      if (bytes > 0) {
        uint8_t *buf = (uint8_t *)BarePoolAcquire(dc->bp, bytes);
        memcpy(buf, receiveBuffer, bytes);
        HandleSctp(dc, client, buf, bytes);
      }
    }
  }
}

static void HandleStun(Dc *dc, const StunPacket *packet,
                       const Address *remote) {
  Client *client =
      FindClientByCreds(dc, &packet->serverUser, &packet->remoteUser);

  if (!client) {
    // TODO: Send unauthorized
    return;
  }

  StunPacket outPacket;
  outPacket.type = Stun_SuccessResponse;
  memcpy(outPacket.transactionId, packet->transactionId,
         kStunTransactionIdLength);
  outPacket.xorMappedAddress.family = Stun_IPV4;
  outPacket.xorMappedAddress.port = ByteSwap(remote->port ^ kStunXorMagic);
  outPacket.xorMappedAddress.address.ipv4 =
      ByteSwap(remote->host ^ kStunCookie);

  uint8_t stunResponse[512];
  size_t serializedSize =
      SerializeStunPacket(&outPacket, client->serverPassword.identifier,
                          client->serverPassword.length, stunResponse, 512);

  client->localSctpPort = remote->port;
  client->address = *remote;

  dc->writeUdpData(stunResponse, serializedSize, client, dc->userData);
}

static void PurgeDeadClients(Dc *dc) {
  for (int32_t i = 0; i < dc->numClients; i++) {
    Client *client = dc->clients[i];
    if (client->ttl <= 0.0 || client->state == Client_WaitingRemoval) {
      Event evt;
      evt.type = Event_ClientLeave;
      evt.client = client;
      PushEvent(dc, evt);
    }
  }
}

static int32_t DcCryptoInit(Dc *dc) {
  static bool initDone = false;

  if (!initDone) {
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    initDone = true;
  }

  dc->sslCtx = SSL_CTX_new(DTLS_server_method());
  if (!dc->sslCtx) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  int sslStatus =
      SSL_CTX_set_cipher_list(dc->sslCtx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
  if (sslStatus != 1) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  SSL_CTX_set_verify(dc->sslCtx, SSL_VERIFY_NONE, NULL);

  Cert cert;

  sslStatus = SSL_CTX_use_PrivateKey(dc->sslCtx, cert.key);

  if (sslStatus != 1) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  sslStatus = SSL_CTX_use_certificate(dc->sslCtx, cert.x509);

  if (sslStatus != 1) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  sslStatus = SSL_CTX_check_private_key(dc->sslCtx);

  if (sslStatus != 1) {
    ERR_print_errors_fp(stderr);
    return 0;
  }

  SSL_CTX_set_options(dc->sslCtx, SSL_OP_NO_QUERY_MTU);

  memcpy(dc->certFingerprint, cert.fingerprint, sizeof(cert.fingerprint));

  return 1;
}

int32_t Create(const char *host, const char *port, int maxClients, Dc **dc) {
  *dc = NULL;

  Dc *ctx = (Dc *)calloc(1, sizeof(Dc));

  if (!ctx) {
    return OUT_OF_MEMORY;
  }

  ctx->bp = (BarePool *)calloc(1, sizeof(BarePool));

  if (!ctx->bp) {
    Destroy(ctx);
    return OUT_OF_MEMORY;
  }

  BarePoolInit(ctx->bp, 1 << 20);

  ctx->time = MsNow() * 0.001;
  ctx->port = atoi(port);
  ctx->pendingEvents = QueueCreate(sizeof(Event), 1024);
  ctx->errorCallback = DefaultErrorCallback;
  ctx->writeUdpData = WriteNothing;

  strncpy(ctx->host, host, sizeof(ctx->host));

  if (!DcCryptoInit(ctx)) {
    Destroy(ctx);
    return ERROR;
  }

  ctx->maxClients = maxClients <= 0 ? 256 : maxClients;
  ctx->clientPool = PoolCreate(sizeof(Client), ctx->maxClients);
  ctx->clients = (Client **)calloc(ctx->maxClients, sizeof(Client *));

  *dc = ctx;
  return OK;
}

static void SendHeartbeat(Dc *dc, Client *client) {
  SctpPacket packet;
  packet.sourcePort = dc->port;
  packet.destionationPort = client->remoteSctpPort;
  packet.verificationTag = client->sctpVerificationTag;

  SctpChunk rc;
  rc.type = Sctp_Heartbeat;
  rc.flags = kSctpFlagCompleteUnreliable;
  rc.length = SctpChunkLength(4 + 8);
  rc.as.heartbeat.heartbeatInfo = (const uint8_t *)&dc->time;
  rc.as.heartbeat.heartbeatInfoLen = sizeof(dc->time);

  SendSctp(dc, client, &packet, &rc, 1);
}

static void UpdateClients(Dc *dc) {
  double t = MsNow() * 0.001;
  dc->dt = t - dc->time;
  dc->time = t;

  for (int32_t i = 0; i < dc->numClients; i++) {
    Client *client = dc->clients[i];
    client->ttl -= dc->dt;
    client->nextHeartbeat -= dc->dt;

    if (client->nextHeartbeat <= 0.0) {
      client->nextHeartbeat = heartbeatInterval;
      SendHeartbeat(dc, client);
    }

    ClientSendPendingDTLS(dc, client);
  }
}

int32_t Update(Dc *dc, Event *evt) {
  if (QueuePop(dc->pendingEvents, evt)) {
    return 1;
  }

  UpdateClients(dc);
  BarePoolReset(dc->bp);

  PurgeDeadClients(dc);

  return 0;
}

static int32_t SendData(Dc *dc, Client *client, const uint8_t *data,
                        int32_t length, DataChanProtoIdentifier proto) {
  if (client->state < Client_DataChannelOpen) {
    return -1;
  }

  SctpPacket packet;
  packet.sourcePort = dc->port;
  packet.destionationPort = client->remoteSctpPort;
  packet.verificationTag = client->sctpVerificationTag;

  SctpChunk rc;
  rc.type = Sctp_Data;
  rc.flags = kSctpFlagCompleteUnreliable;
  rc.length = SctpDataChunkLength(length);

  auto *chunkData = &rc.as.data;
  chunkData->tsn = client->tsn++;
  chunkData->streamId = 0; // TODO: Does it matter?
  chunkData->streamSeq = 0;
  chunkData->protoId = proto;
  chunkData->userData = data;
  chunkData->userDataLength = length;

  SendSctp(dc, client, &packet, &rc, 1);
  return 0;
}

int32_t SendText(Dc *dc, Client *client, const char *text, int32_t length) {
  return SendData(dc, client, (const uint8_t *)text, length, DCProto_String);
}

int32_t SendBinary(Dc *dc, Client *client, const uint8_t *data,
                   int32_t length) {
  return SendData(dc, client, data, length, DCProto_Binary);
}

SDPResult ExchangeSDP(Dc *dc, const char *sdp, int32_t length) {
  ICESdpFields iceFields;
  if (!ParseSdp(sdp, length, &iceFields)) {
    return {SDPStatus_InvalidSDP, NULL, NULL, 0};
  }

  Client *client = NewClient(dc);

  if (!client) {
    return {SDPStatus_MaxClients, NULL, NULL, 0};
  }

  client->serverUser.length = 4;
  RandomString((char *)client->serverUser.identifier,
               client->serverUser.length);
  client->serverPassword.length = 24;
  RandomString((char *)client->serverPassword.identifier,
               client->serverPassword.length);
  memcpy(client->remoteUser.identifier, iceFields.ufrag.value,
         Min(iceFields.ufrag.length, kMaxStunIdentifierLength));
  client->remoteUser.length = iceFields.ufrag.length;
  memcpy(client->remoteUserPassword.identifier, iceFields.password.value,
         Min(iceFields.password.length, kMaxStunIdentifierLength));

  int sdpLength = 0;
  const char *responseSdp = GenerateSDP(
      dc->bp, dc->certFingerprint, dc->host, dc->port,
      (char *)client->serverUser.identifier, client->serverUser.length,
      (char *)client->serverPassword.identifier, client->serverPassword.length,
      &iceFields, &sdpLength);

  if (!responseSdp) {
    return {SDPStatus_Error, NULL, NULL, 0};
  }

  return {SDPStatus_Success, client, responseSdp, sdpLength};
}

void SetUserData(Dc *dc, void *userData) { dc->userData = userData; }

void HandleUDP(Dc *dc, const Address *remote, const uint8_t *data,
               int32_t length) {
  StunPacket stunPacket;
  if (ParseStun(data, length, &stunPacket)) {
    HandleStun(dc, &stunPacket, remote);
  } else {
    ReceiveDTLSPacket(dc, data, length, remote);
  }
}

void SetUDPWriteFunction(Dc *dc, WriteFn write) { dc->writeUdpData = write; }

Address ClientGetAddress(const Client *client) { return client->address; }

void SetErrorCallback(Dc *dc, ErrorFn callback) {
  if (callback) {
    dc->errorCallback = callback;
  } else {
    dc->errorCallback = DefaultErrorCallback;
  }
}

void Destroy(Dc *dc) {
  if (!dc) {
    return;
  }

  free(dc);
}

Client *FindClient(const Dc *dc, Address address) {
  for (int32_t i = 0; i < dc->numClients; i++) {
    Client *c = dc->clients[i];

    if (c->address.host == address.host && c->address.port == address.port) {
      return c;
    }
  }

  return NULL;
}
