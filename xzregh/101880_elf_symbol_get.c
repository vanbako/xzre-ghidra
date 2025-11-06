// /home/kali/xzre-ghidra/xzregh/101880_elf_symbol_get.c
// Function: elf_symbol_get @ 0x101880
// Calling convention: __stdcall
// Prototype: Elf64_Sym * __stdcall elf_symbol_get(elf_info_t * elf_info, EncodedStringId encoded_string_id, EncodedStringId sym_version)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Looks up an ELF symbol from a parsed ELF
 *
 *   @param elf_info the parsed ELF context
 *   @param encoded_string_id string ID of the symbol name
 *   @param sym_version optional string representing the symbol version (e.g. "GLIBC_2.2.5")
 *   @return Elf64_Sym* pointer to the ELF symbol, or NULL if not found
 */

Elf64_Sym *
elf_symbol_get(elf_info_t *elf_info,EncodedStringId encoded_string_id,EncodedStringId sym_version)

{
  ushort uVar1;
  uint uVar2;
  u32 *puVar3;
  char *pcVar4;
  u32 uVar5;
  BOOL BVar6;
  EncodedStringId EVar7;
  Elf64_Sym *vaddr;
  ulong uVar8;
  ushort *vaddr_00;
  Elf64_Verdef *vaddr_01;
  uint uVar9;
  uint *vaddr_02;
  u32 *local_40;
  uint local_34;
  
  BVar6 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x58,0xf,3,0);
  if ((BVar6 != 0) && ((sym_version == 0 || ((elf_info->flags & 0x18) == 0x18)))) {
    for (uVar9 = 0; uVar9 < elf_info->gnu_hash_nbuckets; uVar9 = uVar9 + 1) {
      puVar3 = elf_info->gnu_hash_buckets;
      BVar6 = elf_contains_vaddr(elf_info,puVar3 + uVar9,4,4);
      if (BVar6 == 0) {
        return (Elf64_Sym *)0x0;
      }
      uVar2 = puVar3[uVar9];
      puVar3 = elf_info->gnu_hash_chain;
      BVar6 = elf_contains_vaddr(elf_info,puVar3 + uVar2,8,4);
      local_40 = puVar3 + uVar2;
      if (BVar6 == 0) {
        return (Elf64_Sym *)0x0;
      }
      do {
        uVar8 = (long)local_40 - (long)elf_info->gnu_hash_chain >> 2 & 0xffffffff;
        vaddr = elf_info->symtab + uVar8;
        BVar6 = elf_contains_vaddr(elf_info,vaddr,0x18,4);
        if (BVar6 == 0) {
          return (Elf64_Sym *)0x0;
        }
        if ((vaddr->st_value != 0) && (vaddr->st_shndx != 0)) {
          uVar2 = vaddr->st_name;
          pcVar4 = elf_info->strtab;
          BVar6 = elf_contains_vaddr(elf_info,pcVar4 + uVar2,1,4);
          if (BVar6 == 0) {
            return (Elf64_Sym *)0x0;
          }
          EVar7 = get_string_id(pcVar4 + uVar2,(char *)0x0);
          if (EVar7 == encoded_string_id) {
            if (sym_version == 0) {
              return vaddr;
            }
            vaddr_00 = (ushort *)(uVar8 * 2 + (long)elf_info->versym);
            BVar6 = elf_contains_vaddr(elf_info,vaddr_00,2,4);
            if (BVar6 == 0) {
              return (Elf64_Sym *)0x0;
            }
            uVar1 = *vaddr_00;
            if (((elf_info->flags & 0x18) == 0x18) && ((uVar1 & 0x7ffe) != 0)) {
              vaddr_01 = elf_info->verdef;
              local_34 = 0;
              do {
                if (((elf_info->verdef_num <= (ulong)local_34) ||
                    (BVar6 = elf_contains_vaddr(elf_info,vaddr_01,0x14,4), BVar6 == 0)) ||
                   ((short)*vaddr_01 != 1)) break;
                if ((uVar1 & 0x7fff) == *(ushort *)((long)vaddr_01 + 4)) {
                  vaddr_02 = (uint *)((ulong)*(uint *)((long)vaddr_01 + 0xc) + (long)vaddr_01);
                  BVar6 = elf_contains_vaddr(elf_info,vaddr_02,8,4);
                  if (BVar6 == 0) break;
                  uVar2 = *vaddr_02;
                  pcVar4 = elf_info->strtab;
                  BVar6 = elf_contains_vaddr(elf_info,pcVar4 + uVar2,1,4);
                  if (BVar6 == 0) break;
                  EVar7 = get_string_id(pcVar4 + uVar2,(char *)0x0);
                  if (sym_version == EVar7) {
                    return vaddr;
                  }
                }
                if ((uint)vaddr_01[2] == 0) break;
                local_34 = local_34 + 1;
                vaddr_01 = (Elf64_Verdef *)((long)vaddr_01 + (ulong)(uint)vaddr_01[2]);
              } while( true );
            }
          }
        }
        uVar5 = *local_40;
        local_40 = local_40 + 1;
      } while ((uVar5 & 1) == 0);
    }
  }
  return (Elf64_Sym *)0x0;
}

