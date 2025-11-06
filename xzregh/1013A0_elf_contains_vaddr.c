// /home/kali/xzre-ghidra/xzregh/1013A0_elf_contains_vaddr.c
// Function: elf_contains_vaddr @ 0x1013A0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_contains_vaddr(elf_info_t * elf_info, void * vaddr, u64 size, u32 p_flags)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief checks if given ELF file contains the range [vaddr, vaddr+size)
 *   in a segment with the specified memory protection flags
 *
 *   @param elf_info elf context
 *   @param vaddr starting memory address
 *   @param size memory size
 *   @param p_flags the expected segment protection flags (PF_*)
 *   @return BOOL TRUE if found, FALSE otherwise
 */

BOOL elf_contains_vaddr(elf_info_t *elf_info,void *vaddr,u64 size,u32 p_flags)

{
  BOOL BVar1;
  
  BVar1 = elf_contains_vaddr_impl(elf_info,vaddr,size,p_flags);
  return BVar1;
}

