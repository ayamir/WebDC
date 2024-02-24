#include "BarePool.h"
#include <assert.h>
#include <stdlib.h>

void BarePoolInit(BarePool *bp, int32_t capacity) {
  bp->memory = (uint8_t *)calloc(capacity, 1);
  bp->length = 0;
  bp->capacity = capacity;
}

void *BarePoolAcquire(BarePool *bp, int32_t blockSize) {
  assert(blockSize > 0);
  int32_t remain = bp->capacity - bp->length;

  if (remain >= blockSize) {
    uint8_t *m = bp->memory + bp->length;
    bp->length += blockSize;
    return m;
  }

  return NULL;
}

void BarePoolReset(BarePool *bp) { bp->length = 0; }

void BarePoolDestroy(BarePool *bp) { free(bp->memory); }
