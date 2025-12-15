// /home/kali/xzre-ghidra/xzregh/10A860_count_bits.c
// Function: count_bits @ 0x10A860
// Calling convention: __stdcall
// Prototype: u32 __stdcall count_bits(u64 x)


/*
 * AutoDoc: Wegner-style popcount loop over a 64-bit mask. The trie walker and the secret-data helpers use it to turn bitmap nodes into child indexes without storing per-node counts.
 */
#include "xzre_types.h"

u32 count_bits(u64 x)

{
  u32 bit_count;
  u32 result;
  
  bit_count = 0;
  // AutoDoc: Classic Wegner popcount: repeatedly clear the low bit until the mask is empty, incrementing the tally each time.
  for (; x != 0; x = x & x - 1) {
    bit_count = bit_count + 1;
  }
  return bit_count;
}

