#include "Host.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  const char *hostAddr = "127.0.0.1";
  const char *port = "9555";
  int32_t maxClients = 256;

  if (argc > 2) {
    hostAddr = argv[1];
    port = argv[2];
  }

  Host *host = NULL;

  int32_t status = HostCreate(hostAddr, port, maxClients, &host);
  if (status != WU_OK) {
    printf("failed to create host\n");
    return 1;
  }

  for (;;) {
    Event evt;
    while (HostServe(host, &evt, 0)) {
      switch (evt.type) {
      case Event_ClientJoin: {
        printf("EchoServer: client join\n");
        break;
      }
      case Event_ClientLeave: {
        printf("EchoServer: client leave\n");
        HostRemoveClient(host, evt.client);
        break;
      }
      case Event_TextData: {
        const char *text = (const char *)evt.data;
        int32_t length = evt.length;
        HostSendText(host, evt.client, text, length);
        break;
      }
      case Event_BinaryData: {
        HostSendBinary(host, evt.client, evt.data, evt.length);
        break;
      }
      default:
        break;
      }
    }
  }

  return 0;
}
