// /home/kali/xzre-ghidra/xzregh/1013D0_elf_parse.c
// Function: elf_parse @ 0x1013D0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_parse(Elf64_Ehdr * ehdr, elf_info_t * elf_info)


/*
 * AutoDoc: Initialises an `elf_info_t` from an in-memory ELF header: zeroes every field, records the lowest PT_LOAD virtual address, locates the PT_DYNAMIC segment, and caches pointers to the strtab, symtab, relocation tables (PLT, RELA, RELR), GNU hash buckets, version records, and GNU_RELRO metadata. Each pointer retrieved from the dynamic table is validated with `elf_contains_vaddr` so forged headers are rejected.
 *
 * It also enforces invariants such as 'only one PT_GNU_RELRO segment', derives the number of dynamic entries, and flips feature bits (`flags`) so later helpers know whether RELR, versym, or gnurelro data is present. Failure to locate the dynamic segment, find the required headers, or keep derived pointers inside mapped memory causes the parse to abort with FALSE.
 */
#include "xzre_types.h"


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
  BOOL BVar13;
  int iVar14;
  Elf64_Dyn *vaddr;
  _union_4 *p_Var15;
  int iVar16;
  long lVar17;
  Elf64_Xword EVar18;
  u64 *puVar19;
  Elf64_Phdr *pEVar20;
  ulong uVar21;
  Elf64_Phdr *pEVar22;
  ulong uVar23;
  uint uVar24;
  Elf64_Xword size;
  Elf64_Xword size_00;
  uint *puVar25;
  u32 *hash_chain;
  gnu_hash_table_t *hash_buckets;
  u64 *hash_bloom;
  BOOL have_verdef_num;
  u64 d_relrsz;
  u64 d_relasz;
  u64 d_pltrelsz;
  gnu_hash_table_t *gnu_hash;
  Elf64_Dyn *dyn;
  Elf64_Phdr *dyn_phdr;
  int dynamic_idx;
  u64 first_vaddr;
  Elf64_Phdr *phdr;
  int i;
  
  if (ehdr == (Elf64_Ehdr *)0x0) {
    return 0;
  }
  if (elf_info != (elf_info_t *)0x0) {
    uVar21 = 0xffffffffffffffff;
    uVar24 = 0;
    puVar19 = &elf_info->first_vaddr;
    for (lVar17 = 0x3e; lVar17 != 0; lVar17 = lVar17 + -1) {
      *(undefined4 *)puVar19 = 0;
      puVar19 = (u64 *)((long)puVar19 + 4);
    }
    elf_info->elfbase = ehdr;
    lVar17 = -1;
    uVar23 = (ulong)ehdr->e_phnum;
    pEVar20 = (Elf64_Phdr *)(ehdr->e_ident + ehdr->e_phoff);
    *(Elf64_Half *)&elf_info->e_phnum = ehdr->e_phnum;
    elf_info->phdrs = pEVar20;
    pEVar22 = pEVar20;
    for (; uVar24 < (uint)uVar23; uVar24 = uVar24 + 1) {
      p_type = pEVar22->p_type;
      if (p_type == 1) {
        if (pEVar22->p_vaddr < uVar21) {
          uVar21 = pEVar22->p_vaddr;
        }
      }
      else if (p_type == 2) {
        lVar17 = (long)(int)uVar24;
      }
      else {
        BVar13 = is_gnu_relro(p_type,0xa0000000);
        if (BVar13 != 0) {
          if (elf_info->gnurelro_found != 0) {
            return 0;
          }
          elf_info->gnurelro_vaddr = pEVar22->p_vaddr;
          EVar18 = pEVar22->p_memsz;
          elf_info->gnurelro_found = 1;
          elf_info->gnurelro_memsize = EVar18;
        }
      }
      pEVar22 = pEVar22 + 1;
    }
    if ((uVar21 != 0xffffffffffffffff) && ((int)lVar17 != -1)) {
      elf_info->first_vaddr = uVar21;
      uVar23 = pEVar20[lVar17].p_memsz;
      vaddr = (Elf64_Dyn *)((long)ehdr + (pEVar20[lVar17].p_vaddr - uVar21));
      elf_info->dyn = vaddr;
      iVar14 = (int)(uVar23 >> 4);
      *(int *)&elf_info->dyn_num_entries = iVar14;
      BVar13 = elf_contains_vaddr(elf_info,vaddr,uVar23,4);
      if (BVar13 != 0) {
        p_Var15 = &vaddr->d_un;
        bVar12 = false;
        size = 0xffffffffffffffff;
        size_00 = 0xffffffffffffffff;
        EVar18 = 0xffffffffffffffff;
        puVar25 = (uint *)0x0;
        for (iVar16 = 0; iVar14 != iVar16; iVar16 = iVar16 + 1) {
          lVar17 = ((Elf64_Dyn *)(p_Var15 + -1))->d_tag;
          if (lVar17 == 0) {
            *(int *)&elf_info->dyn_num_entries = iVar16;
            break;
          }
          if (lVar17 < 0x25) {
            if (lVar17 < 0x17) {
              switch(lVar17) {
              case 2:
                EVar18 = p_Var15->d_val;
                break;
              case 5:
                elf_info->strtab = (char *)*(Elf64_Xword *)p_Var15;
                break;
              case 6:
                elf_info->symtab = (Elf64_Sym *)*(Elf64_Xword *)p_Var15;
                break;
              case 7:
                elf_info->rela_relocs = (Elf64_Rela *)*(Elf64_Xword *)p_Var15;
                break;
              case 8:
                size_00 = p_Var15->d_val;
              }
            }
            else {
              switch(lVar17) {
              case 0x17:
                elf_info->plt_relocs = (Elf64_Rela *)*(Elf64_Xword *)p_Var15;
                break;
              case 0x18:
                goto switchD_0010157d_caseD_18;
              case 0x1e:
                bVar11 = *(byte *)p_Var15 & 8;
                goto LAB_00101650;
              case 0x23:
                size = p_Var15->d_val;
                break;
              case 0x24:
                elf_info->relr_relocs = (Elf64_Relr *)*(Elf64_Xword *)p_Var15;
              }
            }
          }
          else if (lVar17 == 0x6ffffffb) {
            bVar11 = *(byte *)p_Var15 & 1;
LAB_00101650:
            if (bVar11 != 0) {
switchD_0010157d_caseD_18:
              elf_info->flags = elf_info->flags | 0x20;
            }
          }
          else if (lVar17 < 0x6ffffffc) {
            if (lVar17 < 0x6ffffefd) {
              if (0x6ffffefa < lVar17) {
                return 0;
              }
              if (lVar17 == 0x6ffffef5) {
                puVar25 = (uint *)p_Var15->d_val;
              }
            }
            else if (lVar17 == 0x6ffffff0) {
              _Var4.d_val = *(Elf64_Xword *)p_Var15;
              elf_info->flags = elf_info->flags | 0x10;
              elf_info->versym = (Elf64_Versym *)_Var4;
            }
          }
          else if (lVar17 == 0x6ffffffd) {
            bVar12 = true;
            elf_info->verdef_num = *(Elf64_Xword *)p_Var15;
          }
          else {
            if (lVar17 == 0x7fffffff) {
              return 0;
            }
            if (lVar17 == 0x6ffffffc) {
              elf_info->verdef = (Elf64_Verdef *)*(Elf64_Xword *)p_Var15;
            }
          }
          p_Var15 = p_Var15 + 2;
        }
        pEVar5 = elf_info->plt_relocs;
        if (pEVar5 != (Elf64_Rela *)0x0) {
          if (EVar18 == 0xffffffffffffffff) {
            return 0;
          }
          elf_info->flags = elf_info->flags | 1;
          auVar9._8_8_ = 0;
          auVar9._0_8_ = EVar18;
          elf_info->plt_relocs_num = SUB164(auVar9 / ZEXT816(0x18),0);
        }
        pEVar6 = elf_info->rela_relocs;
        if (pEVar6 != (Elf64_Rela *)0x0) {
          if (size_00 == 0xffffffffffffffff) {
            return 0;
          }
          elf_info->flags = elf_info->flags | 2;
          auVar10._8_8_ = 0;
          auVar10._0_8_ = size_00;
          elf_info->rela_relocs_num = SUB164(auVar10 / ZEXT816(0x18),0);
        }
        pEVar7 = elf_info->relr_relocs;
        if (pEVar7 != (Elf64_Relr *)0x0) {
          if (size == 0xffffffffffffffff) {
            return 0;
          }
          elf_info->flags = elf_info->flags | 4;
          elf_info->relr_relocs_num = (u32)(size >> 3);
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
        if (((pEVar8 != (Elf64_Ehdr *)0x0) && (puVar25 != (uint *)0x0)) &&
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
            puVar25 = (uint *)((long)puVar25 + (long)ehdr);
          }
          pEVar8 = (Elf64_Ehdr *)elf_info->verdef;
          if ((pEVar8 != (Elf64_Ehdr *)0x0) && (pEVar8 < ehdr)) {
            elf_info->verdef = (Elf64_Verdef *)(pEVar8->e_ident + (long)ehdr->e_ident);
          }
          if (((((elf_info->plt_relocs == (Elf64_Rela *)0x0) ||
                (BVar13 = elf_contains_vaddr(elf_info,elf_info->plt_relocs,EVar18,4), BVar13 != 0))
               && ((elf_info->rela_relocs == (Elf64_Rela *)0x0 ||
                   (BVar13 = elf_contains_vaddr(elf_info,elf_info->rela_relocs,size_00,4),
                   BVar13 != 0)))) &&
              ((elf_info->relr_relocs == (Elf64_Relr *)0x0 ||
               (BVar13 = elf_contains_vaddr(elf_info,elf_info->relr_relocs,size,4), BVar13 != 0))))
             && ((elf_info->verdef == (Elf64_Verdef *)0x0 ||
                 (BVar13 = elf_contains_vaddr(elf_info,elf_info->verdef,elf_info->verdef_num * 0x14,
                                              4), BVar13 != 0)))) {
            uVar24 = *puVar25;
            elf_info->gnu_hash_nbuckets = uVar24;
            uVar1 = puVar25[2];
            uVar2 = puVar25[1];
            elf_info->gnu_hash_last_bloom = uVar1 - 1;
            uVar3 = puVar25[3];
            elf_info->gnu_hash_bloom = (u64 *)(puVar25 + 4);
            puVar25 = (uint *)((long)(puVar25 + 4) + (ulong)(uVar1 * 2) * 4);
            elf_info->gnu_hash_bloom_shift = uVar3;
            elf_info->gnu_hash_buckets = puVar25;
            elf_info->gnu_hash_chain = puVar25 + ((ulong)uVar24 - (ulong)uVar2);
            return 1;
          }
        }
      }
    }
  }
  return 0;
}

