#include "Dc.h"
#include "Fuzz.h"

int main(int argc, char **argv) {
  if (argc < 2)
    return 1;

  size_t length = 0;
  uint8_t *content = LoadFile(argv[1], &length);

  Dc *dc = nullptr;
  const char *host = "127.0.0.1";
  const char *port = "5000";
  int maxClients = 256;

  if (!Create(host, port, maxClients, &dc)) {
    return 0;
  }

  if (content) {
    ExchangeSDP(dc, (const char *)content, length);
  }

  return 0;
}
