// /home/kali/xzre-ghidra/xzregh/1013A0_elf_contains_vaddr.c
// Function: elf_contains_vaddr @ 0x1013A0
// Calling convention: unknown
// Prototype: undefined elf_contains_vaddr(void)


/*
 * AutoDoc: Thin wrapper around `elf_contains_vaddr_impl` that keeps the public API surface simple. Every range-checker in the loader funnels through it so the flag handling, recursion guard, and alignment fixes stay centralized, making it easy to detect when a pointer falls outside the parsed ELF image.
 */
#include "xzre_types.h"


void elf_contains_vaddr(void)

{
  elf_contains_vaddr_impl();
  return;
}

