// /home/kali/xzre-ghidra/xzregh/1013D0_elf_parse.c
// Function: elf_parse @ 0x1013D0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_parse(Elf64_Ehdr * ehdr, elf_info_t * elf_info)


/*
 * AutoDoc: Initialises an `elf_info_t` from an in-memory ELF header: zeroes every field, records the lowest PT_LOAD virtual address,
 * locates the PT_DYNAMIC segment, and caches pointers to the strtab, symtab, relocation tables (PLT, RELA, RELR), GNU hash
 * buckets, version records, and GNU_RELRO metadata. Each pointer retrieved from the dynamic table is validated with
 * `elf_contains_vaddr` so forged headers are rejected.
 *
 * It also enforces invariants such as 'only one PT_GNU_RELRO segment', derives the number of dynamic entries, and flips feature
 * bits (`flags`) so later helpers know whether RELR, versym, or gnurelro data is present. Failure to locate the dynamic segment,
 * find the required headers, or keep derived pointers inside mapped memory causes the parse to abort with FALSE.
 */

#include "xzre_types.h"

BOOL elf_parse(Elf64_Ehdr *ehdr,elf_info_t *elf_info)

{
  Elf64_Word p_type;
  uint gnu_hash_bloom_size;
  uint gnu_hash_symbias;
  uint gnu_hash_bloom_shift;
  Elf64_DynValue versym_value;
  Elf64_Rela *plt_relocs_ptr;
  Elf64_Rela *rela_relocs_ptr;
  Elf64_Relr *relr_relocs_ptr;
  char *strtab_base;
  undefined1 auVar9 [16];
  undefined1 auVar10 [16];
  byte bind_now_flag;
  BOOL verdef_present;
  BOOL range_ok;
  int dyn_entry_capacity;
  Elf64_Dyn *vaddr;
  Elf64_DynValue *dyn_cursor;
  int dyn_index;
  long dynamic_phdr_index;
  Elf64_Xword pltrel_table_size;
  u64 *puVar19;
  Elf64_Phdr *phdrs;
  ulong min_load_vaddr;
  Elf64_Phdr *phdr_cursor;
  ulong phnum;
  uint phdr_idx;
  Elf64_Xword relr_table_size;
  Elf64_Xword rela_table_size;
  uint *gnu_hash_header;
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
    return FALSE;
  }
  if (elf_info != (elf_info_t *)0x0) {
    min_load_vaddr = 0xffffffffffffffff;
    phdr_idx = 0;
    puVar19 = &elf_info->load_base_vaddr;
    for (dynamic_phdr_index = 0x3e; dynamic_phdr_index != 0; dynamic_phdr_index = dynamic_phdr_index + -1) {
      *(undefined4 *)puVar19 = 0;
      puVar19 = (u64 *)((long)puVar19 + 4);
    }
    elf_info->elfbase = ehdr;
    dynamic_phdr_index = -1;
    phnum = (ulong)ehdr->e_phnum;
    phdrs = (Elf64_Phdr *)(ehdr->e_ident + ehdr->e_phoff);
    *(Elf64_Half *)&elf_info->phdr_count = ehdr->e_phnum;
    elf_info->phdrs = phdrs;
    phdr_cursor = phdrs;
    for (; phdr_idx < (uint)phnum; phdr_idx = phdr_idx + 1) {
      p_type = phdr_cursor->p_type;
      if (p_type == 1) {
        if (phdr_cursor->p_vaddr < min_load_vaddr) {
          min_load_vaddr = phdr_cursor->p_vaddr;
        }
      }
      else if (p_type == 2) {
        dynamic_phdr_index = (long)(int)phdr_idx;
      }
      else {
        range_ok = is_gnu_relro(p_type,0xa0000000);
        if (range_ok != FALSE) {
          if (elf_info->gnurelro_present != FALSE) {
            return FALSE;
          }
          elf_info->gnurelro_vaddr = phdr_cursor->p_vaddr;
          pltrel_table_size = phdr_cursor->p_memsz;
          elf_info->gnurelro_present = TRUE;
          elf_info->gnurelro_memsize = pltrel_table_size;
        }
      }
      phdr_cursor = phdr_cursor + 1;
    }
    if ((min_load_vaddr != 0xffffffffffffffff) && ((int)dynamic_phdr_index != -1)) {
      elf_info->load_base_vaddr = min_load_vaddr;
      phnum = phdrs[dynamic_phdr_index].p_memsz;
      vaddr = (Elf64_Dyn *)((long)ehdr + (phdrs[dynamic_phdr_index].p_vaddr - min_load_vaddr));
      elf_info->dynamic_segment = vaddr;
      dyn_entry_capacity = (int)(phnum >> 4);
      *(int *)&elf_info->dyn_entry_count = dyn_entry_capacity;
      range_ok = elf_contains_vaddr(elf_info,vaddr,phnum,4);
      if (range_ok != FALSE) {
        dyn_cursor = &vaddr->d_un;
        verdef_present = FALSE;
        relr_table_size = 0xffffffffffffffff;
        rela_table_size = 0xffffffffffffffff;
        pltrel_table_size = 0xffffffffffffffff;
        gnu_hash_header = (uint *)0x0;
        for (dyn_index = 0; dyn_entry_capacity != dyn_index; dyn_index = dyn_index + 1) {
          dynamic_phdr_index = ((Elf64_Dyn *)(dyn_cursor + -1))->d_tag;
          if (dynamic_phdr_index == 0) {
            *(int *)&elf_info->dyn_entry_count = dyn_index;
            break;
          }
          if (dynamic_phdr_index < 0x25) {
            if (dynamic_phdr_index < 0x17) {
              switch(dynamic_phdr_index) {
              case 2:
                pltrel_table_size = dyn_cursor->d_val;
                break;
              case 5:
                elf_info->dynstr = (char *)*(Elf64_Xword *)dyn_cursor;
                break;
              case 6:
                elf_info->dynsym = (Elf64_Sym *)*(Elf64_Xword *)dyn_cursor;
                break;
              case 7:
                elf_info->rela_relocs = (Elf64_Rela *)*(Elf64_Xword *)dyn_cursor;
                break;
              case 8:
                rela_table_size = dyn_cursor->d_val;
              }
            }
            else {
              switch(dynamic_phdr_index) {
              case 0x17:
                elf_info->plt_relocs = (Elf64_Rela *)*(Elf64_Xword *)dyn_cursor;
                break;
              case 0x18:
                goto switchD_0010157d_caseD_18;
              case 0x1e:
                bind_now_flag = *(byte *)dyn_cursor & 8;
                goto LAB_00101650;
              case 0x23:
                relr_table_size = dyn_cursor->d_val;
                break;
              case 0x24:
                elf_info->relr_relocs = (Elf64_Relr *)*(Elf64_Xword *)dyn_cursor;
              }
            }
          }
          else if (dynamic_phdr_index == 0x6ffffffb) {
            bind_now_flag = *(byte *)dyn_cursor & 1;
LAB_00101650:
            if (bind_now_flag != 0) {
switchD_0010157d_caseD_18:
              *(byte *)&elf_info->feature_flags = (byte)elf_info->feature_flags | 0x20;
            }
          }
          else if (dynamic_phdr_index < 0x6ffffffc) {
            if (dynamic_phdr_index < 0x6ffffefd) {
              if (0x6ffffefa < dynamic_phdr_index) {
                return FALSE;
              }
              if (dynamic_phdr_index == 0x6ffffef5) {
                gnu_hash_header = (uint *)dyn_cursor->d_val;
              }
            }
            else if (dynamic_phdr_index == 0x6ffffff0) {
              versym_value.d_val = *(Elf64_Xword *)dyn_cursor;
              *(byte *)&elf_info->feature_flags = (byte)elf_info->feature_flags | 0x10;
              elf_info->versym = (Elf64_Versym *)versym_value;
            }
          }
          else if (dynamic_phdr_index == 0x6ffffffd) {
            verdef_present = TRUE;
            elf_info->verdef_count = *(Elf64_Xword *)dyn_cursor;
          }
          else {
            if (dynamic_phdr_index == 0x7fffffff) {
              return FALSE;
            }
            if (dynamic_phdr_index == 0x6ffffffc) {
              elf_info->verdef = (Elf64_Verdef *)*(Elf64_Xword *)dyn_cursor;
            }
          }
          dyn_cursor = dyn_cursor + 2;
        }
        plt_relocs_ptr = elf_info->plt_relocs;
        if (plt_relocs_ptr != (Elf64_Rela *)0x0) {
          if (pltrel_table_size == 0xffffffffffffffff) {
            return FALSE;
          }
          *(byte *)&elf_info->feature_flags = (byte)elf_info->feature_flags | 1;
          *(u64 *)(auVar9 + 8) = 0;
          *(u64 *)auVar9 = pltrel_table_size;
          elf_info->plt_reloc_count = SUB164(auVar9 / ZEXT816(0x18),0);
        }
        rela_relocs_ptr = elf_info->rela_relocs;
        if (rela_relocs_ptr != (Elf64_Rela *)0x0) {
          if (rela_table_size == 0xffffffffffffffff) {
            return FALSE;
          }
          *(byte *)&elf_info->feature_flags = (byte)elf_info->feature_flags | 2;
          *(u64 *)(auVar10 + 8) = 0;
          *(u64 *)auVar10 = rela_table_size;
          elf_info->rela_reloc_count = SUB164(auVar10 / ZEXT816(0x18),0);
        }
        relr_relocs_ptr = elf_info->relr_relocs;
        if (relr_relocs_ptr != (Elf64_Relr *)0x0) {
          if (relr_table_size == 0xffffffffffffffff) {
            return FALSE;
          }
          *(byte *)&elf_info->feature_flags = (byte)elf_info->feature_flags | 4;
          elf_info->relr_reloc_count = (u32)(relr_table_size >> 3);
        }
        if (elf_info->verdef != (Elf64_Verdef *)0x0) {
          if (verdef_present) {
            *(byte *)&elf_info->feature_flags = (byte)elf_info->feature_flags | 8;
          }
          else {
            elf_info->verdef = (Elf64_Verdef *)0x0;
          }
        }
        strtab_base = (Elf64_Ehdr *)elf_info->dynstr;
        if (((strtab_base != (Elf64_Ehdr *)0x0) && (gnu_hash_header != (uint *)0x0)) &&
           (elf_info->dynsym != (Elf64_Sym *)0x0)) {
          if (strtab_base <= ehdr) {
            elf_info->dynstr = (char *)(ehdr->e_ident + (long)strtab_base->e_ident);
            elf_info->dynsym = (Elf64_Sym *)(ehdr->e_ident + (long)&elf_info->dynsym->st_name);
            if (plt_relocs_ptr != (Elf64_Rela *)0x0) {
              elf_info->plt_relocs = (Elf64_Rela *)(ehdr->e_ident + (long)&plt_relocs_ptr->r_offset);
            }
            if (rela_relocs_ptr != (Elf64_Rela *)0x0) {
              elf_info->rela_relocs = (Elf64_Rela *)(ehdr->e_ident + (long)&rela_relocs_ptr->r_offset);
            }
            if (relr_relocs_ptr != (Elf64_Relr *)0x0) {
              elf_info->relr_relocs = (Elf64_Relr *)((long)relr_relocs_ptr + (long)ehdr);
            }
            if (elf_info->versym != (Elf64_Versym *)0x0) {
              elf_info->versym = (Elf64_Versym *)((long)elf_info->versym + (long)ehdr);
            }
            gnu_hash_header = (uint *)((long)gnu_hash_header + (long)ehdr);
          }
          strtab_base = (Elf64_Ehdr *)elf_info->verdef;
          if ((strtab_base != (Elf64_Ehdr *)0x0) && (strtab_base < ehdr)) {
            elf_info->verdef = (Elf64_Verdef *)(strtab_base->e_ident + (long)ehdr->e_ident);
          }
          if (((((elf_info->plt_relocs == (Elf64_Rela *)0x0) ||
                (range_ok = elf_contains_vaddr(elf_info,elf_info->plt_relocs,pltrel_table_size,4),
                range_ok != FALSE)) &&
               ((elf_info->rela_relocs == (Elf64_Rela *)0x0 ||
                (range_ok = elf_contains_vaddr(elf_info,elf_info->rela_relocs,rela_table_size,4),
                range_ok != FALSE)))) &&
              ((elf_info->relr_relocs == (Elf64_Relr *)0x0 ||
               (range_ok = elf_contains_vaddr(elf_info,elf_info->relr_relocs,relr_table_size,4), range_ok != FALSE)
               ))) && ((elf_info->verdef == (Elf64_Verdef *)0x0 ||
                       (range_ok = elf_contains_vaddr(elf_info,elf_info->verdef,
                                                    elf_info->verdef_count * 0x14,4),
                       range_ok != FALSE)))) {
            phdr_idx = *gnu_hash_header;
            elf_info->gnu_hash_nbuckets = phdr_idx;
            gnu_hash_bloom_size = gnu_hash_header[2];
            gnu_hash_symbias = gnu_hash_header[1];
            elf_info->gnu_hash_last_bloom = gnu_hash_bloom_size - 1;
            gnu_hash_bloom_shift = gnu_hash_header[3];
            elf_info->gnu_hash_bloom = (u64 *)(gnu_hash_header + 4);
            gnu_hash_header = (uint *)((long)(gnu_hash_header + 4) + (ulong)(gnu_hash_bloom_size * 2) * 4);
            elf_info->gnu_hash_bloom_shift = gnu_hash_bloom_shift;
            elf_info->gnu_hash_buckets = gnu_hash_header;
            elf_info->gnu_hash_chain = gnu_hash_header + ((ulong)phdr_idx - (ulong)gnu_hash_symbias);
            return TRUE;
          }
        }
      }
    }
  }
  return FALSE;
}

