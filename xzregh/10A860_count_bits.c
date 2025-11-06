// /home/kali/xzre-ghidra/xzregh/10A860_count_bits.c
// Function: count_bits @ 0x10A860
// Calling convention: __stdcall
// Prototype: u32 __stdcall count_bits(u64 x)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief returns the number of 1 bits in x
 *
 *   @param x
 *   @return u32 number of 1 bits
 *
 * Upstream implementation excerpt (xzre/xzre_code/count_bits.c):
 *     u32 count_bits(u64 x){
 *     	u32 result;
 *     	for(result=0; x; ++result, x &= x-1);
 *     	return result;
 *     }
 */

u32 count_bits(u64 x)

{
  u32 result;
  
  result = 0;
  for (; x != 0; x = x & x - 1) {
    result = result + 1;
  }
  return result;
}

