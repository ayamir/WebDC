#pragma once

#include "Dc.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Host Host;

int32_t HostCreate(const char *hostAddr, const char *port, int32_t maxClients,
                   Host **host);
void HostDestroy(Host *host);
/*
 * Timeout:
 *  -1 = Block until an event
 *   0 = Return immediately
 *  >0 = Block for N milliseconds
 * Returns 1 if an event was received, 0 otherwise.
 */
int32_t HostServe(Host *host, Event *evt, int timeout);
void HostRemoveClient(Host *dc, Client *client);
int32_t HostSendText(Host *host, Client *client, const char *text,
                     int32_t length);
int32_t HostSendBinary(Host *host, Client *client, const uint8_t *data,
                       int32_t length);
void HostSetErrorCallback(Host *host, ErrorFn callback);
Client *HostFindClient(const Host *host, Address address);
#ifdef __cplusplus
}
#endif
