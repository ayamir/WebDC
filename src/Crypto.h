#pragma once

#include <openssl/x509.h>
#include <stddef.h>
#include <stdint.h>

const size_t kSHA1Length = 20;

struct SHA1Digest {
  uint8_t bytes[kSHA1Length];
};

struct Cert {
  Cert();
  ~Cert();

  EVP_PKEY *key;
  X509 *x509;
  char fingerprint[96];
};

SHA1Digest SHA1(const uint8_t *src, size_t len, const void *key, size_t keyLen);
