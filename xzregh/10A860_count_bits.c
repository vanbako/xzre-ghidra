// /home/kali/xzre-ghidra/xzregh/10A860_count_bits.c
// Function: count_bits @ 0x10A860
// Calling convention: __stdcall
// Prototype: u32 __stdcall count_bits(u64 x)
/*
 * AutoDoc: Classic popcount loop that returns the number of set bits in a 64-bit value. The string-id trie and several instruction filters rely on it when they compress lookup tables for pattern matching.
 */

#include "xzre_types.h"


u32 count_bits(u64 x)

{
  u32 result;
  
  result = 0;
  for (; x != 0; x = x & x - 1) {
    result = result + 1;
  }
  return result;
}

