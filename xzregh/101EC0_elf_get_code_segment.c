// /home/kali/xzre-ghidra/xzregh/101EC0_elf_get_code_segment.c
// Function: elf_get_code_segment @ 0x101EC0
// Calling convention: __stdcall
// Prototype: void * __stdcall elf_get_code_segment(elf_info_t * elf_info, u64 * pSize)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Obtains the address and size of the first executable segment in the given ELF file
 *
 *   @param elf_info the parsed ELF context, which will be updated with the address and size of the code segment
 *   @param pSize variable that will be populated with the page-aligned segment size
 *   @return void* the page-aligned starting address of the segment
 */

void * elf_get_code_segment(elf_info_t *elf_info,u64 *pSize)

{
  BOOL BVar1;
  ulong uVar2;
  void *pvVar3;
  Elf64_Phdr *pEVar4;
  ulong uVar5;
  u64 uVar6;
  long lVar7;
  
  BVar1 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0xcb,7,0xc);
  pvVar3 = (void *)0x0;
  if (BVar1 != 0) {
    pvVar3 = (void *)elf_info->code_segment_start;
    if (pvVar3 == (void *)0x0) {
      for (lVar7 = 0; (uint)lVar7 < (uint)(ushort)elf_info->e_phnum; lVar7 = lVar7 + 1) {
        pEVar4 = elf_info->phdrs + lVar7;
        if ((pEVar4->p_type == 1) && ((pEVar4->p_flags & 1) != 0)) {
          uVar2 = (long)elf_info->elfbase + (pEVar4->p_vaddr - elf_info->first_vaddr);
          uVar5 = pEVar4->p_memsz + uVar2;
          pvVar3 = (void *)(uVar2 & 0xfffffffffffff000);
          if ((uVar5 & 0xfff) != 0) {
            uVar5 = (uVar5 & 0xfffffffffffff000) + 0x1000;
          }
          uVar6 = uVar5 - (long)pvVar3;
          elf_info->code_segment_start = (u64)pvVar3;
          elf_info->code_segment_size = uVar6;
          goto LAB_00101f65;
        }
      }
    }
    else {
      uVar6 = elf_info->code_segment_size;
LAB_00101f65:
      *pSize = uVar6;
    }
  }
  return pvVar3;
}

