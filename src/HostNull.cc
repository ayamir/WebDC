#include "Host.h"

int32_t HostCreate(const char *, const char *, int32_t, Host **host) {
  *host = NULL;
  return WU_OK;
}
int32_t HostServe(Host *, Event *, int) { return 0; }
void HostRemoveClient(Host *, Client *) {}
int32_t HostSendText(Host *, Client *, const char *, int32_t) { return 0; }
int32_t HostSendBinary(Host *, Client *, const uint8_t *, int32_t) { return 0; }
void HostSetErrorCallback(Host *, ErrorFn) {}
