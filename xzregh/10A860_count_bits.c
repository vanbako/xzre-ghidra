// /home/kali/xzre-ghidra/xzregh/10A860_count_bits.c
// Function: count_bits @ 0x10A860
// Calling convention: unknown
// Prototype: undefined count_bits(void)


/*
 * AutoDoc: Classic popcount loop that returns the number of set bits in a 64-bit value. The string-id trie and several instruction filters rely on it when they compress lookup tables for pattern matching.
 */
#include "xzre_types.h"


int count_bits(ulong param_1)

{
  int iVar1;
  
  iVar1 = 0;
  for (; param_1 != 0; param_1 = param_1 & param_1 - 1) {
    iVar1 = iVar1 + 1;
  }
  return iVar1;
}

