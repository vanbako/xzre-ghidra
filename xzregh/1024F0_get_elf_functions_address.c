// /home/kali/xzre-ghidra/xzregh/1024F0_get_elf_functions_address.c
// Function: get_elf_functions_address @ 0x1024F0
// Calling convention: __stdcall
// Prototype: elf_functions_t * __stdcall get_elf_functions_address(void)


/*
 * AutoDoc: Same pattern for the `elf_functions_t` dispatch table: start from the relocation-safe sentinel (`elf_functions_offset` lives near `fake_lzma_allocator_offset` in `.data`) and advance 12 struct slots to arrive at the live table. The convoluted pointer math lets the object carry offsets instead of absolute addresses, which keeps the relocation surface tiny while still giving the loader a stable way to reach its helper vtable.
 */

#include "xzre_types.h"

elf_functions_t * get_elf_functions_address(void)

{
  uint local_14;
  elf_functions_t *local_10;
  
  local_10 = (elf_functions_t *)fake_lzma_allocator_offset;
  for (local_14 = 0; local_14 < 0xc; local_14 = local_14 + 1) {
    local_10 = local_10 + 1;
  }
  return local_10;
}

