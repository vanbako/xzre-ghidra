// /home/kali/xzre-ghidra/xzregh/1013A0_elf_contains_vaddr.c
// Function: elf_contains_vaddr @ 0x1013A0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_contains_vaddr(elf_info_t * elf_info, void * vaddr, u64 size, u32 p_flags)


/*
 * AutoDoc: Thin wrapper around `elf_contains_vaddr_impl` that keeps the public API surface simple. Every range-checker in the loader funnels through it so the flag handling, recursion guard, and alignment fixes stay centralized, making it easy to detect when a pointer falls outside the parsed ELF image.
 */
#include "xzre_types.h"

BOOL elf_contains_vaddr(elf_info_t *elf_info,void *vaddr,u64 size,u32 p_flags)

{
  BOOL range_ok;
  
  // AutoDoc: Delegate the heavy lifting (alignment, recursion depth, and flag filtering) to the recursive helper.
  range_ok = elf_contains_vaddr_impl(elf_info,vaddr,size,p_flags);
  return range_ok;
}

