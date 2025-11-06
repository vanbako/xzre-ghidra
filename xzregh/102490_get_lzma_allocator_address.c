// /home/kali/xzre-ghidra/xzregh/102490_get_lzma_allocator_address.c
// Function: get_lzma_allocator_address @ 0x102490
// Calling convention: __stdcall
// Prototype: fake_lzma_allocator_t * __stdcall get_lzma_allocator_address(void)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief gets the address of the fake LZMA allocator
 *
 *   uses fake_lzma_allocator_offset to get the address 0x180 bytes before fake_lzma_allocator
 *   and then adds 0x160 to get the final address of fake_lzma_allocator
 *
 *   called in get_lzma_allocator()
 *
 *   @return fake_lzma_allocator_t*
 */

fake_lzma_allocator_t * get_lzma_allocator_address(void)

{
  uint local_14;
  fake_lzma_allocator_t *local_10;
  
  local_10 = (fake_lzma_allocator_t *)fake_lzma_allocator;
  for (local_14 = 0; local_14 < 0xc; local_14 = local_14 + 1) {
    local_10 = local_10 + 1;
  }
  return local_10;
}

