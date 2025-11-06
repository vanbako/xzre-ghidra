// /home/kali/xzre-ghidra/xzregh/1024F0_get_elf_functions_address.c
// Function: get_elf_functions_address @ 0x1024F0
// Calling convention: __stdcall
// Prototype: elf_functions_t * __stdcall get_elf_functions_address(void)


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

