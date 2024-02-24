#include "Pool.h"
#include <assert.h>
#include <stdlib.h>

struct BlockHeader {
  int32_t index;
};

struct Pool {
  int32_t slotSize;
  int32_t numBytes;
  int32_t numBlocks;
  uint8_t *memory;
  int32_t freeIndicesCount;
  int32_t *freeIndices;
};

Pool *PoolCreate(int32_t blockSize, int32_t numBlocks) {
  Pool *pool = (Pool *)calloc(1, sizeof(Pool));

  pool->slotSize = blockSize + sizeof(BlockHeader);
  pool->numBytes = pool->slotSize * numBlocks;
  pool->numBlocks = numBlocks;
  pool->memory = (uint8_t *)calloc(pool->numBytes, 1);
  pool->freeIndicesCount = numBlocks;
  pool->freeIndices = (int32_t *)calloc(numBlocks, sizeof(int32_t));

  for (int32_t i = 0; i < numBlocks; i++) {
    pool->freeIndices[i] = numBlocks - i - 1;
  }

  return pool;
}

void PoolDestroy(Pool *pool) {
  free(pool->memory);
  free(pool->freeIndices);
  free(pool);
}

void *PoolAcquire(Pool *pool) {
  if (pool->freeIndicesCount == 0)
    return NULL;

  const int32_t index = pool->freeIndices[pool->freeIndicesCount - 1];
  pool->freeIndicesCount--;
  const int32_t offset = index * pool->slotSize;

  uint8_t *block = pool->memory + offset;
  BlockHeader *header = (BlockHeader *)block;
  header->index = index;

  uint8_t *userMem = block + sizeof(BlockHeader);
  return userMem;
}

void PoolRelease(Pool *pool, void *ptr) {
  uint8_t *mem = (uint8_t *)ptr - sizeof(BlockHeader);
  assert(mem >= pool->memory && mem < pool->memory + pool->numBytes);
  BlockHeader *header = (BlockHeader *)mem;
  pool->freeIndices[pool->freeIndicesCount++] = header->index;
}
