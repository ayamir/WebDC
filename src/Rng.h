#pragma once

#include <stddef.h>
#include <stdint.h>

// http://xoroshiro.di.unimi.it/xoroshiro128plus.c
struct RngState {
  uint64_t s[2];
};

uint64_t GetRngSeed();
void RngInit(RngState *state, uint64_t seed);
uint64_t RngNext(RngState *state);
uint64_t RandomU64();
uint32_t RandomU32();

void RandomString(char *out, size_t length);
