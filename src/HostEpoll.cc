#include "Host.h"
#include "Http.h"
#include "Network.h"
#include "Pool.h"
#include "String.h"
#include "picohttpparser.h"
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct ConnectionBuffer {
  size_t size = 0;
  int fd = -1;
  uint8_t requestBuffer[kMaxHttpRequestLength];
};

struct Host {
  Dc *dc;
  int tcpfd;
  int udpfd;
  int epfd;
  int pollTimeout;
  Pool *bufferPool;
  struct epoll_event *events;
  int32_t maxEvents;
  uint16_t port;
  char errBuf[512];
};

static void HostReclaimBuffer(Host *host, ConnectionBuffer *buffer) {
  buffer->fd = -1;
  buffer->size = 0;
  PoolRelease(host->bufferPool, buffer);
}

static ConnectionBuffer *HostGetBuffer(Host *host) {
  ConnectionBuffer *buffer = (ConnectionBuffer *)PoolAcquire(host->bufferPool);
  return buffer;
}

static void HandleErrno(Host *host, const char *description) {
  snprintf(host->errBuf, sizeof(host->errBuf), "%s: %s", description,
           strerror(errno));
  ReportError(host->dc, host->errBuf);
}

static void WriteUDPData(const uint8_t *data, size_t length,
                         const Client *client, void *userData) {
  Host *host = (Host *)userData;

  Address address = ClientGetAddress(client);
  struct sockaddr_in netaddr;
  netaddr.sin_family = AF_INET;
  netaddr.sin_port = htons(address.port);
  netaddr.sin_addr.s_addr = htonl(address.host);

  sendto(host->udpfd, data, length, 0, (struct sockaddr *)&netaddr,
         sizeof(netaddr));
}

static void HandleHttpRequest(Host *host, ConnectionBuffer *conn) {
  for (;;) {
    ssize_t count = read(conn->fd, conn->requestBuffer + conn->size,
                         kMaxHttpRequestLength - conn->size);
    if (count == -1) {
      if (errno != EAGAIN) {
        HandleErrno(host, "failed to read from TCP socket");
        close(conn->fd);
        HostReclaimBuffer(host, conn);
      }
      return;
    } else if (count == 0) {
      close(conn->fd);
      HostReclaimBuffer(host, conn);
      return;
    }

    size_t prevSize = conn->size;
    conn->size += count;

    const char *method;
    const char *path;
    size_t methodLength, pathLength;
    int minorVersion;
    struct phr_header headers[16];
    size_t numHeaders = 16;
    int parseStatus = phr_parse_request(
        (const char *)conn->requestBuffer, conn->size, &method, &methodLength,
        &path, &pathLength, &minorVersion, headers, &numHeaders, prevSize);

    if (parseStatus > 0) {
      size_t contentLength = 0;
      for (size_t i = 0; i < numHeaders; i++) {
        if (CompareCaseInsensitive(headers[i].name, headers[i].name_len,
                                   STRLIT("content-length"))) {
          contentLength = StringToUint(headers[i].value, headers[i].value_len);
          break;
        }
      }

      if (contentLength > 0) {
        if (conn->size == parseStatus + contentLength) {
          const SDPResult sdp = ExchangeSDP(
              host->dc, (const char *)conn->requestBuffer + parseStatus,
              contentLength);

          if (sdp.status == SDPStatus_Success) {
            char response[4096];
            int responseLength =
                snprintf(response, sizeof(response),
                         "HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/json\r\n"
                         "Content-Length: %d\r\n"
                         "Connection: close\r\n"
                         "Access-Control-Allow-Origin: *\r\n"
                         "\r\n%.*s",
                         sdp.sdpLength, sdp.sdpLength, sdp.sdp);
            SocketWrite(conn->fd, response, responseLength);
          } else if (sdp.status == SDPStatus_MaxClients) {
            SocketWrite(conn->fd, STRLIT(HTTP_UNAVAILABLE));
          } else if (sdp.status == SDPStatus_InvalidSDP) {
            SocketWrite(conn->fd, STRLIT(HTTP_BAD_REQUEST));
          } else {
            SocketWrite(conn->fd, STRLIT(HTTP_SERVER_ERROR));
          }

          close(conn->fd);
          HostReclaimBuffer(host, conn);
        }
      }

      return;
    } else if (parseStatus == -1) {
      close(conn->fd);
      HostReclaimBuffer(host, conn);
      return;
    } else {
      if (conn->size == kMaxHttpRequestLength) {
        SocketWrite(conn->fd, STRLIT(HTTP_BAD_REQUEST));
        close(conn->fd);
        HostReclaimBuffer(host, conn);
        return;
      }
    }
  }
}

int32_t HostServe(Host *host, Event *evt, int timeout) {
  int32_t hres = Update(host->dc, evt);

  if (hres) {
    return hres;
  }

  int n = epoll_wait(host->epfd, host->events, host->maxEvents, timeout);

  for (int i = 0; i < n; i++) {
    struct epoll_event *e = &host->events[i];
    ConnectionBuffer *c = (ConnectionBuffer *)e->data.ptr;

    if ((e->events & EPOLLERR) || (e->events & EPOLLHUP) ||
        (!(e->events & EPOLLIN))) {
      close(c->fd);
      HostReclaimBuffer(host, c);
      continue;
    }

    if (host->tcpfd == c->fd) {
      for (;;) {
        struct sockaddr_in inAddress;
        socklen_t inLength = sizeof(inAddress);

        int infd =
            accept(host->tcpfd, (struct sockaddr *)&inAddress, &inLength);
        if (infd == -1) {
          if (errno != EAGAIN && errno != EWOULDBLOCK) {
            HandleErrno(host, "TCP accept");
          }
          break;
        }

        if (MakeNonBlocking(infd) == -1) {
          close(infd);
          continue;
        }

        ConnectionBuffer *conn = HostGetBuffer(host);

        if (conn) {
          conn->fd = infd;
          struct epoll_event event;
          event.events = EPOLLIN | EPOLLET;
          event.data.ptr = conn;
          if (epoll_ctl(host->epfd, EPOLL_CTL_ADD, infd, &event) == -1) {
            close(infd);
            HandleErrno(host, "EPOLL_CTL_ADD infd");
          }
        } else {
          close(infd);
        }
      }
    } else if (host->udpfd == c->fd) {
      struct sockaddr_in remote;
      socklen_t remoteLen = sizeof(remote);
      uint8_t buf[4096];

      ssize_t r = 0;
      while ((r = recvfrom(host->udpfd, buf, sizeof(buf), 0,
                           (struct sockaddr *)&remote, &remoteLen)) > 0) {
        Address address;
        address.host = ntohl(remote.sin_addr.s_addr);
        address.port = ntohs(remote.sin_port);
        HandleUDP(host->dc, &address, buf, r);
      }

    } else {
      HandleHttpRequest(host, c);
    }
  }

  return 0;
}

int32_t HostCreate(const char *hostAddr, const char *port, int32_t maxClients,
                   Host **host) {
  *host = NULL;

  Host *ctx = (Host *)calloc(1, sizeof(Host));

  if (!ctx) {
    return OUT_OF_MEMORY;
  }

  int32_t status = Create(hostAddr, port, maxClients, &ctx->dc);

  if (status != OK) {
    free(ctx);
    return status;
  }

  ctx->tcpfd = CreateSocket(port, ST_TCP);

  if (ctx->tcpfd == -1) {
    HostDestroy(ctx);
    return ERROR;
  }

  status = MakeNonBlocking(ctx->tcpfd);
  if (status == -1) {
    HostDestroy(ctx);
    return ERROR;
  }

  status = listen(ctx->tcpfd, SOMAXCONN);
  if (status == -1) {
    HostDestroy(ctx);
    return ERROR;
  }

  ctx->udpfd = CreateSocket(port, ST_UDP);

  if (ctx->udpfd == -1) {
    HostDestroy(ctx);
    return ERROR;
  }

  status = MakeNonBlocking(ctx->udpfd);
  if (status == -1) {
    HostDestroy(ctx);
    return ERROR;
  }

  ctx->epfd = epoll_create1(0);
  if (ctx->epfd == -1) {
    HostDestroy(ctx);
    return ERROR;
  }

  const int32_t maxEvents = 128;
  ctx->bufferPool = PoolCreate(sizeof(ConnectionBuffer), maxEvents + 2);

  if (!ctx->bufferPool) {
    HostDestroy(ctx);
    return OUT_OF_MEMORY;
  }

  ConnectionBuffer *udpBuf = HostGetBuffer(ctx);
  udpBuf->fd = ctx->udpfd;

  ConnectionBuffer *tcpBuf = HostGetBuffer(ctx);
  tcpBuf->fd = ctx->tcpfd;

  struct epoll_event event;
  event.data.ptr = tcpBuf;
  event.events = EPOLLIN | EPOLLET;

  status = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->tcpfd, &event);
  if (status == -1) {
    HostDestroy(ctx);
    return ERROR;
  }

  event.data.ptr = udpBuf;
  status = epoll_ctl(ctx->epfd, EPOLL_CTL_ADD, ctx->udpfd, &event);
  if (status == -1) {
    HostDestroy(ctx);
    return ERROR;
  }

  ctx->maxEvents = maxEvents;
  ctx->events = (struct epoll_event *)calloc(ctx->maxEvents, sizeof(event));

  if (!ctx->events) {
    HostDestroy(ctx);
    return OUT_OF_MEMORY;
  }

  SetUserData(ctx->dc, ctx);
  SetUDPWriteFunction(ctx->dc, WriteUDPData);

  *host = ctx;

  return OK;
}

void HostRemoveClient(Host *host, Client *client) {
  RemoveClient(host->dc, client);
}

int32_t HostSendText(Host *host, Client *client, const char *text,
                     int32_t length) {
  return SendText(host->dc, client, text, length);
}

int32_t HostSendBinary(Host *host, Client *client, const uint8_t *data,
                       int32_t length) {
  return SendBinary(host->dc, client, data, length);
}

void HostSetErrorCallback(Host *host, ErrorFn callback) {
  SetErrorCallback(host->dc, callback);
}

void HostDestroy(Host *host) {
  if (!host) {
    return;
  }

  Destroy(host->dc);

  if (host->tcpfd != -1) {
    close(host->tcpfd);
  }

  if (host->udpfd != -1) {
    close(host->udpfd);
  }

  if (host->epfd != -1) {
    close(host->epfd);
  }

  if (host->bufferPool) {
    free(host->bufferPool);
  }

  if (host->events) {
    free(host->events);
  }
}

Client *HostFindClient(const Host *host, Address address) {
  return FindClient(host->dc, address);
}
