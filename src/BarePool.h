#pragma once

#include <stdint.h>

struct BarePool {
  uint8_t *memory;
  int32_t length;
  int32_t capacity;
};

void BarePoolInit(BarePool *bp, int32_t capacity);
void *BarePoolAcquire(BarePool *bp, int32_t blockSize);
void BarePoolReset(BarePool *bp);
void BarePoolDestroy(BarePool *bp);
