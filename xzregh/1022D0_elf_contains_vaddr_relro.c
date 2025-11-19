// /home/kali/xzre-ghidra/xzregh/1022D0_elf_contains_vaddr_relro.c
// Function: elf_contains_vaddr_relro @ 0x1022D0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_contains_vaddr_relro(elf_info_t * elf_info, u64 vaddr, u64 size, u32 p_flags)


/*
 * AutoDoc: Combines `elf_contains_vaddr` with the GNU_RELRO metadata harvested during `elf_parse`. The range must sit inside a read-only
 * PT_LOAD (PF_R), and the module must have advertised a RELRO segment; if so the helper also verifies that `[vaddr, vaddr+size)`
 * falls within the page-aligned RELRO window cached in `elf_info_t`. Anything outside that protected span returns FALSE, which
 * prevents the loader from treating writable data as RELRO by mistake.
 */

#include "xzre_types.h"

BOOL elf_contains_vaddr_relro(elf_info_t *elf_info,u64 vaddr,u64 size,u32 p_flags)

{
  BOOL range_ok;
  ulong relro_end;
  ulong relro_start;
  
  range_ok = elf_contains_vaddr(elf_info,(void *)vaddr,size,2);
  if (((range_ok != FALSE) && (range_ok = TRUE, p_flags != 0)) && (elf_info->gnurelro_present != FALSE)) {
    relro_start = (long)elf_info->elfbase + (elf_info->gnurelro_vaddr - elf_info->load_base_vaddr);
    relro_end = elf_info->gnurelro_memsize + relro_start;
    relro_start = relro_start & 0xfffffffffffff000;
    if ((relro_end & 0xfff) != 0) {
      relro_end = (relro_end & 0xfffffffffffff000) + 0x1000;
    }
    if ((relro_end <= vaddr) || (range_ok = FALSE, vaddr < relro_start)) {
      range_ok = (BOOL)(vaddr + size <= relro_start && vaddr < relro_start || relro_end < vaddr + size);
    }
  }
  return range_ok;
}

