// /home/kali/xzre-ghidra/xzregh/1013D0_elf_parse.c
// Function: elf_parse @ 0x1013D0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_parse(Elf64_Ehdr * ehdr, elf_info_t * elf_info)


/*
 * AutoDoc: Initialises an `elf_info_t` from an in-memory ELF header: zeroes every field, records the lowest PT_LOAD virtual address, locates the PT_DYNAMIC segment, and caches pointers to the strtab, symtab, relocation tables (PLT, RELA, RELR), GNU hash buckets, version records, and GNU_RELRO metadata. Each derived pointer is validated with `elf_contains_vaddr`, and the parser keeps feature bits synchronized so later helpers know which tables were present.
 *
 * It enforces invariants such as "only one PT_GNU_RELRO segment", derives the number of dynamic entries, honours BIND_NOW/RELR/versym toggles, and refuses to trust any header that leaves the module boundaries.
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
  u64 pltrel_count_dividend[2];
  u64 rela_count_dividend[2];
  byte bind_now_flag;
  BOOL verdef_present;
  BOOL range_valid;
  int dyn_entry_capacity;
  Elf64_Dyn *vaddr;
  Elf64_DynValue *dyn_entry_fields;
  int dyn_entry_index;
  long dynamic_phdr_idx;
  Elf64_Xword pltrel_table_size;
  u64 *info_wipe_cursor;
  Elf64_Phdr *program_headers;
  ulong lowest_load_vaddr;
  Elf64_Phdr *phdr_scan;
  ulong phnum;
  uint phdr_index;
  Elf64_Xword relr_table_size;
  Elf64_Xword rela_table_size;
  uint *gnu_hash_header_words;
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
    lowest_load_vaddr = 0xffffffffffffffff;
    phdr_index = 0;
    info_wipe_cursor = &elf_info->load_base_vaddr;
    // AutoDoc: Clear the cached `elf_info_t` with a fixed-count wipe so partially parsed state never leaks across runs.
    for (dynamic_phdr_idx = 0x3e; dynamic_phdr_idx != 0; dynamic_phdr_idx = dynamic_phdr_idx + -1) {
      *(u32 *)info_wipe_cursor = 0;
      info_wipe_cursor = (u64 *)((long)info_wipe_cursor + 4);
    }
    elf_info->elfbase = ehdr;
    dynamic_phdr_idx = -1;
    phnum = (ulong)ehdr->e_phnum;
    program_headers = (Elf64_Phdr *)(ehdr->e_ident + ehdr->e_phoff);
    *(Elf64_Half *)&elf_info->phdr_count = ehdr->e_phnum;
    elf_info->phdrs = program_headers;
    phdr_scan = program_headers;
    for (; phdr_index < (uint)phnum; phdr_index = phdr_index + 1) {
      p_type = phdr_scan->p_type;
      if (p_type == 1) {
        if (phdr_scan->p_vaddr < lowest_load_vaddr) {
          lowest_load_vaddr = phdr_scan->p_vaddr;
        }
      }
      else if (p_type == 2) {
        dynamic_phdr_idx = (long)(int)phdr_index;
      }
      else {
        range_valid = is_gnu_relro(p_type,0xa0000000);
        if (range_valid != FALSE) {
          // AutoDoc: Reject binaries that declare more than one PT_GNU_RELRO span; overlapping RELRO metadata would be suspicious.
          if (elf_info->gnurelro_present != FALSE) {
            return FALSE;
          }
          elf_info->gnurelro_vaddr = phdr_scan->p_vaddr;
          pltrel_table_size = phdr_scan->p_memsz;
          elf_info->gnurelro_present = TRUE;
          elf_info->gnurelro_memsize = pltrel_table_size;
        }
      }
      phdr_scan = phdr_scan + 1;
    }
    if ((lowest_load_vaddr != 0xffffffffffffffff) && ((int)dynamic_phdr_idx != -1)) {
      elf_info->load_base_vaddr = lowest_load_vaddr;
      phnum = program_headers[dynamic_phdr_idx].p_memsz;
      vaddr = (Elf64_Dyn *)((long)ehdr + (program_headers[dynamic_phdr_idx].p_vaddr - lowest_load_vaddr));
      elf_info->dynamic_segment = vaddr;
      dyn_entry_capacity = (int)(phnum >> 4);
      *(int *)&elf_info->dyn_entry_count = dyn_entry_capacity;
      // AutoDoc: Reject the ELF immediately if the PT_DYNAMIC payload does not live entirely inside readable memory.
      range_valid = elf_contains_vaddr(elf_info,vaddr,phnum,4);
      if (range_valid != FALSE) {
        dyn_entry_fields = &vaddr->d_un;
        verdef_present = FALSE;
        relr_table_size = 0xffffffffffffffff;
        rela_table_size = 0xffffffffffffffff;
        pltrel_table_size = 0xffffffffffffffff;
        gnu_hash_header_words = (uint *)0x0;
        for (dyn_entry_index = 0; dyn_entry_capacity != dyn_entry_index; dyn_entry_index = dyn_entry_index + 1) {
          dynamic_phdr_idx = ((Elf64_Dyn *)(dyn_entry_fields + -1))->d_tag;
          if (dynamic_phdr_idx == 0) {
            *(int *)&elf_info->dyn_entry_count = dyn_entry_index;
            break;
          }
          if (dynamic_phdr_idx < 0x25) {
            if (dynamic_phdr_idx < 0x17) {
              switch(dynamic_phdr_idx) {
              // AutoDoc: DT_PLTRELSZ: record the byte size of the PLT relocation table so we can later derive `plt_reloc_count`.
              case 2:
                pltrel_table_size = dyn_entry_fields->d_val;
                break;
              case 5:
                elf_info->dynstr = (char *)*(Elf64_Xword *)dyn_entry_fields;
                break;
              case 6:
                elf_info->dynsym = (Elf64_Sym *)*(Elf64_Xword *)dyn_entry_fields;
                break;
              case 7:
                elf_info->rela_relocs = (Elf64_Rela *)*(Elf64_Xword *)dyn_entry_fields;
                break;
              case 8:
                rela_table_size = dyn_entry_fields->d_val;
              }
            }
            else {
              switch(dynamic_phdr_idx) {
              // AutoDoc: DT_JMPREL: address of the PLT relocation table (Elf64_Rela entries for R_X86_64_JUMP_SLOT).
              case 0x17:
                elf_info->plt_relocs = (Elf64_Rela *)*(Elf64_Xword *)dyn_entry_fields;
                break;
              case 0x18:
                goto switchD_0010157d_caseD_18;
              case 0x1e:
                bind_now_flag = *(byte *)dyn_entry_fields & 8;
                goto LAB_00101650;
              // AutoDoc: DT_RELRSZ: byte size of the packed RELR relocation stream; required before accepting a DT_RELR pointer.
              case 0x23:
                relr_table_size = dyn_entry_fields->d_val;
                break;
              // AutoDoc: DT_RELR: base address of the packed RELR relocation stream (bitmap/literal entries for R_X86_64_RELATIVE).
              case 0x24:
                elf_info->relr_relocs = (Elf64_Relr *)*(Elf64_Xword *)dyn_entry_fields;
              }
            }
          }
          else if (dynamic_phdr_idx == 0x6ffffffb) {
            bind_now_flag = *(byte *)dyn_entry_fields & 1;
LAB_00101650:
            if (bind_now_flag != 0) {
switchD_0010157d_caseD_18:
              // AutoDoc: Treat DT_BIND_NOW/DT_FLAGS(DF_BIND_NOW)/DT_FLAGS_1(DF_1_NOW) as a single "bind now" feature bit for later helpers.
              *(byte *)&elf_info->feature_flags = (byte)elf_info->feature_flags | 0x20;
            }
          }
          else if (dynamic_phdr_idx < 0x6ffffffc) {
            if (dynamic_phdr_idx < 0x6ffffefd) {
              if (0x6ffffefa < dynamic_phdr_idx) {
                return FALSE;
              }
              // AutoDoc: DT_GNU_HASH: remember the GNU hash header pointer so bucket/chain tables can be derived after relocation pointers are validated.
              if (dynamic_phdr_idx == 0x6ffffef5) {
                gnu_hash_header_words = (uint *)dyn_entry_fields->d_val;
              }
            }
            // AutoDoc: DT_VERSYM: enables `.gnu.version` lookups; set the feature bit and store the versym pointer.
            else if (dynamic_phdr_idx == 0x6ffffff0) {
              versym_value.d_val = *(Elf64_Xword *)dyn_entry_fields;
              *(byte *)&elf_info->feature_flags = (byte)elf_info->feature_flags | 0x10;
              elf_info->versym = (Elf64_Versym *)versym_value;
            }
          }
          else if (dynamic_phdr_idx == 0x6ffffffd) {
            verdef_present = TRUE;
            elf_info->verdef_count = *(Elf64_Xword *)dyn_entry_fields;
          }
          else {
            if (dynamic_phdr_idx == 0x7fffffff) {
              return FALSE;
            }
            // AutoDoc: DT_VERDEF: pointer to `.gnu.version_d` (kept only when DT_VERDEFNUM/size validation succeeds).
            if (dynamic_phdr_idx == 0x6ffffffc) {
              elf_info->verdef = (Elf64_Verdef *)*(Elf64_Xword *)dyn_entry_fields;
            }
          }
          // AutoDoc: `dyn_entry_fields` points at `d_un`, so advancing by 2 words steps to the next 16-byte `Elf64_Dyn` entry.
          dyn_entry_fields = dyn_entry_fields + 2;
        }
        plt_relocs_ptr = elf_info->plt_relocs;
        if (plt_relocs_ptr != (Elf64_Rela *)0x0) {
          if (pltrel_table_size == 0xffffffffffffffff) {
            return FALSE;
          }
          *(byte *)&elf_info->feature_flags = (byte)elf_info->feature_flags | 1;
          pltrel_count_dividend[1] = 0;
          pltrel_count_dividend[0] = pltrel_table_size;
          elf_info->plt_reloc_count = SUB164(pltrel_count_dividend / ZEXT816(0x18),0);
        }
        rela_relocs_ptr = elf_info->rela_relocs;
        if (rela_relocs_ptr != (Elf64_Rela *)0x0) {
          if (rela_table_size == 0xffffffffffffffff) {
            return FALSE;
          }
          *(byte *)&elf_info->feature_flags = (byte)elf_info->feature_flags | 2;
          rela_count_dividend[1] = 0;
          rela_count_dividend[0] = rela_table_size;
          elf_info->rela_reloc_count = SUB164(rela_count_dividend / ZEXT816(0x18),0);
        }
        relr_relocs_ptr = elf_info->relr_relocs;
        if (relr_relocs_ptr != (Elf64_Relr *)0x0) {
          if (relr_table_size == 0xffffffffffffffff) {
            return FALSE;
          }
          *(byte *)&elf_info->feature_flags = (byte)elf_info->feature_flags | 4;
          elf_info->relr_reloc_count = (u32)(relr_table_size >> 3);
        }
        // AutoDoc: Keep the `.gnu.version_d` pointer only when its size metadata also survived validation; otherwise drop the stale handle.
        if (elf_info->verdef != (Elf64_Verdef *)0x0) {
          if (verdef_present) {
            *(byte *)&elf_info->feature_flags = (byte)elf_info->feature_flags | 8;
          }
          else {
            elf_info->verdef = (Elf64_Verdef *)0x0;
          }
        }
        strtab_base = (Elf64_Ehdr *)elf_info->dynstr;
        if (((strtab_base != (Elf64_Ehdr *)0x0) && (gnu_hash_header_words != (uint *)0x0)) &&
           (elf_info->dynsym != (Elf64_Sym *)0x0)) {
          // AutoDoc: Convert relative pointers (PIE layout) into process addresses before recording them in `elf_info_t`.
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
            gnu_hash_header_words = (uint *)((long)gnu_hash_header_words + (long)ehdr);
          }
          strtab_base = (Elf64_Ehdr *)elf_info->verdef;
          if ((strtab_base != (Elf64_Ehdr *)0x0) && (strtab_base < ehdr)) {
            elf_info->verdef = (Elf64_Verdef *)(strtab_base->e_ident + (long)ehdr->e_ident);
          }
          // AutoDoc: Every relocation/metadata pointer gets revalidated before harvesting the GNU hash bucket/chain tables.
          if (((((elf_info->plt_relocs == (Elf64_Rela *)0x0) ||
                (range_valid = elf_contains_vaddr(elf_info,elf_info->plt_relocs,pltrel_table_size,4),
                range_valid != FALSE)) &&
               ((elf_info->rela_relocs == (Elf64_Rela *)0x0 ||
                (range_valid = elf_contains_vaddr(elf_info,elf_info->rela_relocs,rela_table_size,4),
                range_valid != FALSE)))) &&
              ((elf_info->relr_relocs == (Elf64_Relr *)0x0 ||
               (range_valid = elf_contains_vaddr(elf_info,elf_info->relr_relocs,relr_table_size,4), range_valid != FALSE)
               ))) && ((elf_info->verdef == (Elf64_Verdef *)0x0 ||
                       (range_valid = elf_contains_vaddr(elf_info,elf_info->verdef,
                                                    elf_info->verdef_count * 0x14,4),
                       range_valid != FALSE)))) {
            phdr_index = *gnu_hash_header_words;
            elf_info->gnu_hash_nbuckets = phdr_index;
            gnu_hash_bloom_size = gnu_hash_header_words[2];
            gnu_hash_symbias = gnu_hash_header_words[1];
            elf_info->gnu_hash_last_bloom = gnu_hash_bloom_size - 1;
            gnu_hash_bloom_shift = gnu_hash_header_words[3];
            elf_info->gnu_hash_bloom = (u64 *)(gnu_hash_header_words + 4);
            gnu_hash_header_words = (uint *)((long)(gnu_hash_header_words + 4) + (ulong)(gnu_hash_bloom_size * 2) * 4);
            elf_info->gnu_hash_bloom_shift = gnu_hash_bloom_shift;
            elf_info->gnu_hash_buckets = gnu_hash_header_words;
            elf_info->gnu_hash_chain = gnu_hash_header_words + ((ulong)phdr_index - (ulong)gnu_hash_symbias);
            return TRUE;
          }
        }
      }
    }
  }
  return FALSE;
}

