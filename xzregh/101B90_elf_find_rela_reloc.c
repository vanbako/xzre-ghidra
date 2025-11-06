// /home/kali/xzre-ghidra/xzregh/101B90_elf_find_rela_reloc.c
// Function: elf_find_rela_reloc @ 0x101B90
// Calling convention: __stdcall
// Prototype: Elf64_Rela * __stdcall elf_find_rela_reloc(elf_info_t * elf_info, EncodedStringId encoded_string_id, u64 reloc_type)


Elf64_Rela *
elf_find_rela_reloc(elf_info_t *elf_info,EncodedStringId encoded_string_id,u64 reloc_type)

{
  Elf64_Ehdr *pEVar1;
  Elf64_Rela *pEVar2;
  Elf64_Rela *in_RCX;
  ulong uVar3;
  undefined4 in_register_00000034;
  ulong *in_R8;
  
  if (((elf_info->flags & 2) == 0) || (elf_info->rela_relocs_num == 0)) {
    return (Elf64_Rela *)0x0;
  }
  uVar3 = 0;
  if (in_R8 != (ulong *)0x0) {
    uVar3 = *in_R8;
  }
  pEVar1 = elf_info->elfbase;
  do {
    if (elf_info->rela_relocs_num <= uVar3) {
      if (in_R8 != (ulong *)0x0) {
        *in_R8 = uVar3;
      }
      return (Elf64_Rela *)0x0;
    }
    pEVar2 = elf_info->rela_relocs + uVar3;
    if ((int)pEVar2->r_info == 8) {
      if (CONCAT44(in_register_00000034,encoded_string_id) == 0) {
        pEVar2 = (Elf64_Rela *)(pEVar1->e_ident + pEVar2->r_addend);
      }
      else {
        if (pEVar2->r_addend != CONCAT44(in_register_00000034,encoded_string_id) - (long)pEVar1)
        goto LAB_00101c07;
        pEVar2 = (Elf64_Rela *)(pEVar1->e_ident + pEVar2->r_offset);
        if (reloc_type == 0) goto LAB_00101c18;
      }
      if ((reloc_type <= pEVar2) && (pEVar2 <= in_RCX)) {
LAB_00101c18:
        if (in_R8 == (ulong *)0x0) {
          return pEVar2;
        }
        *in_R8 = uVar3 + 1;
        return pEVar2;
      }
    }
LAB_00101c07:
    uVar3 = uVar3 + 1;
  } while( true );
}

