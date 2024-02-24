#pragma once

#include <stdint.h>

struct Pool;

Pool *PoolCreate(int32_t blockSize, int32_t numBlocks);
void PoolDestroy(Pool *pool);
void *PoolAcquire(Pool *pool);
void PoolRelease(Pool *pool, void *ptr);
