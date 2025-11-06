// /home/kali/xzre-ghidra/xzregh/101C30_elf_find_relr_reloc.c
// Function: elf_find_relr_reloc @ 0x101C30
// Calling convention: __stdcall
// Prototype: Elf64_Relr * __stdcall elf_find_relr_reloc(elf_info_t * elf_info, EncodedStringId encoded_string_id)
/*
 * AutoDoc: Generated from reverse engineering.
 *
 * Summary:
 *   Iterates RELR-packed relocations for encoded_string_id, unpacking bitmap runs and validating that each candidate address lies inside the expected PT_LOAD mapping.
 *
 * Notes:
 *   - Accepts optional lower/upper bounds and an iteration cursor to support incremental searches.
 *   - Falls back to NULL when the module does not advertise RELR relocations or no entry matches the encoded id.
 */

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

