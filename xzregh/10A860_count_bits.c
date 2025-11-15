// /home/kali/xzre-ghidra/xzregh/10A860_count_bits.c
// Function: count_bits @ 0x10A860
// Calling convention: __stdcall
// Prototype: u32 __stdcall count_bits(u64 x)


/*
 * AutoDoc: Wegner-style popcount loop over a 64-bit mask. The trie walker and the secret-data helpers use it to turn bitmap nodes into
 * child indexes without storing per-node counts.
 */

#include "xzre_types.h"

u32 count_bits(u64 x)

{
  u32 uVar1;
  u32 result;
  
  uVar1 = 0;
  for (; x != 0; x = x & x - 1) {
    uVar1 = uVar1 + 1;
  }
  return uVar1;
}

