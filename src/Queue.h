#pragma once

#include <stdint.h>

struct Queue {
  int32_t itemSize;
  int32_t start;
  int32_t length;
  int32_t capacity;
  uint8_t *items;
};

Queue *QueueCreate(int32_t itemSize, int32_t capacity);
void QueueInit(Queue *q, int32_t itemSize, int32_t capacity);
void QueuePush(Queue *q, const void *item);
int32_t QueuePop(Queue *q, void *item);
