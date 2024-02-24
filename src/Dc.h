#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OK 0
#define ERROR 1
#define OUT_OF_MEMORY 2

typedef struct Client Client;
typedef struct Dc Dc;
typedef void (*ErrorFn)(const char *err, void *userData);
typedef void (*WriteFn)(const uint8_t *data, size_t length,
                        const Client *client, void *userData);

typedef enum {
  Event_BinaryData,
  Event_ClientJoin,
  Event_ClientLeave,
  Event_TextData
} EventType;

typedef enum {
  SDPStatus_Success,
  SDPStatus_InvalidSDP,
  SDPStatus_MaxClients,
  SDPStatus_Error
} SDPStatus;

typedef struct {
  EventType type;
  Client *client;
  const uint8_t *data;
  int32_t length;
} Event;

typedef struct {
  SDPStatus status;
  Client *client;
  const char *sdp;
  int32_t sdpLength;
} SDPResult;

typedef struct {
  uint32_t host;
  uint16_t port;
} Address;

int32_t Create(const char *host, const char *port, int maxClients, Dc **dc);
void Destroy(Dc *dc);
int32_t Update(Dc *dc, Event *evt);
int32_t SendText(Dc *dc, Client *client, const char *text, int32_t length);
int32_t SendBinary(Dc *dc, Client *client, const uint8_t *data, int32_t length);
void ReportError(Dc *dc, const char *error);
void RemoveClient(Dc *dc, Client *client);
void ClientSetUserData(Client *client, void *user);
void *ClientGetUserData(const Client *client);
SDPResult ExchangeSDP(Dc *dc, const char *sdp, int32_t length);
void HandleUDP(Dc *dc, const Address *remote, const uint8_t *data,
               int32_t length);
void SetUDPWriteFunction(Dc *dc, WriteFn write);
void SetUserData(Dc *dc, void *userData);
void SetErrorCallback(Dc *dc, ErrorFn callback);
Address ClientGetAddress(const Client *client);
Client *FindClient(const Dc *dc, Address address);

#ifdef __cplusplus
}
#endif
