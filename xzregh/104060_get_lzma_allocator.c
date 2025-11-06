// /home/kali/xzre-ghidra/xzregh/104060_get_lzma_allocator.c
// Function: get_lzma_allocator @ 0x104060
// Calling convention: __stdcall
// Prototype: lzma_allocator * __stdcall get_lzma_allocator(void)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief gets the fake LZMA allocator, used for imports resolution
 *   the "opaque" field of the structure holds a pointer to @see elf_info_t
 *
 *   @return lzma_allocator*
 *
 * Upstream implementation excerpt (xzre/xzre_code/get_lzma_allocator.c):
 *     lzma_allocator *get_lzma_allocator(void){
 *     	return &get_lzma_allocator_address()->allocator;
 *     }
 */

lzma_allocator * get_lzma_allocator(void)

{
  fake_lzma_allocator_t *pfVar1;
  
  pfVar1 = get_lzma_allocator_address();
  return &pfVar1->allocator;
}

