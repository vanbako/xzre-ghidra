// /home/kali/xzre-ghidra/xzregh/101880_elf_symbol_get.c
// Function: elf_symbol_get @ 0x101880
// Calling convention: __stdcall
// Prototype: Elf64_Sym * __stdcall elf_symbol_get(elf_info_t * elf_info, EncodedStringId encoded_string_id, EncodedStringId sym_version)


/*
 * AutoDoc: Symbol resolver that trusts the GNU hash table the loader extracted earlier. After setting a telemetry bit it walks each hash
 * bucket, validates the bucket and chain addresses, and replays the classic GNU hash lookup to pull `Elf64_Sym` entries out of
 * `.dynsym`. When a candidate symbol has a non-zero value and section index, the helper hashes the associated string with
 * `get_string_id` and compares it against the requested encoded id.
 *
 * If a symbol version is supplied it additionally consults `.gnu.version`/`.gnu.version_d`: the version index is read from
 * `versym`, then matched against the verifier definitions by walking the linked `verdef` list and comparing the underlying string
 * id. Returning NULL means either the target symbol is missing, the module did not advertise GNU hash+version tables, or the
 * string/relocation pointers failed validation.
 */

#include "xzre_types.h"

Elf64_Sym *
elf_symbol_get(elf_info_t *elf_info,EncodedStringId encoded_string_id,EncodedStringId sym_version)

{
  ushort version_index;
  uint name_offset;
  u32 *gnu_hash_cursor;
  char *candidate_name;
  u32 chain_hash;
  BOOL addr_ok;
  EncodedStringId candidate_id;
  Elf64_Sym *sym;
  ulong symbol_index;
  ushort *versym_slot;
  Elf64_Verdef *verdef_cursor;
  uint bucket_index;
  uint *verdef_name_ptr;
  u32 *chain_entry;
  uint verdef_idx;
  
  addr_ok = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x58,0xf,3,FALSE);
  if ((addr_ok != FALSE) && ((sym_version == 0 || ((elf_info->flags & 0x18) == 0x18)))) {
    for (bucket_index = 0; bucket_index < elf_info->gnu_hash_nbuckets; bucket_index = bucket_index + 1) {
      gnu_hash_cursor = elf_info->gnu_hash_buckets;
      addr_ok = elf_contains_vaddr(elf_info,gnu_hash_cursor + bucket_index,4,4);
      if (addr_ok == FALSE) {
        return (Elf64_Sym *)0x0;
      }
      name_offset = gnu_hash_cursor[bucket_index];
      gnu_hash_cursor = elf_info->gnu_hash_chain;
      addr_ok = elf_contains_vaddr(elf_info,gnu_hash_cursor + name_offset,8,4);
      chain_entry = gnu_hash_cursor + name_offset;
      if (addr_ok == FALSE) {
        return (Elf64_Sym *)0x0;
      }
      do {
        symbol_index = (long)chain_entry - (long)elf_info->gnu_hash_chain >> 2 & 0xffffffff;
        sym = elf_info->symtab + symbol_index;
        addr_ok = elf_contains_vaddr(elf_info,sym,0x18,4);
        if (addr_ok == FALSE) {
          return (Elf64_Sym *)0x0;
        }
        if ((sym->st_value != 0) && (sym->st_shndx != 0)) {
          name_offset = sym->st_name;
          candidate_name = elf_info->strtab;
          addr_ok = elf_contains_vaddr(elf_info,candidate_name + name_offset,1,4);
          if (addr_ok == FALSE) {
            return (Elf64_Sym *)0x0;
          }
          candidate_id = get_string_id(candidate_name + name_offset,(char *)0x0);
          if (candidate_id == encoded_string_id) {
            if (sym_version == 0) {
              return sym;
            }
            versym_slot = (ushort *)(symbol_index * 2 + (long)elf_info->versym);
            addr_ok = elf_contains_vaddr(elf_info,versym_slot,2,4);
            if (addr_ok == FALSE) {
              return (Elf64_Sym *)0x0;
            }
            version_index = *versym_slot;
            if (((elf_info->flags & 0x18) == 0x18) && ((version_index & 0x7ffe) != 0)) {
              verdef_cursor = elf_info->verdef;
              verdef_idx = 0;
              do {
                if (((elf_info->verdef_num <= (ulong)verdef_idx) ||
                    (addr_ok = elf_contains_vaddr(elf_info,verdef_cursor,0x14,4), addr_ok == FALSE)) ||
                   ((short)*verdef_cursor != 1)) break;
                if ((version_index & 0x7fff) == *(ushort *)((long)verdef_cursor + 4)) {
                  verdef_name_ptr = (uint *)((ulong)*(uint *)((long)verdef_cursor + 0xc) + (long)verdef_cursor);
                  addr_ok = elf_contains_vaddr(elf_info,verdef_name_ptr,8,4);
                  if (addr_ok == FALSE) break;
                  name_offset = *verdef_name_ptr;
                  candidate_name = elf_info->strtab;
                  addr_ok = elf_contains_vaddr(elf_info,candidate_name + name_offset,1,4);
                  if (addr_ok == FALSE) break;
                  candidate_id = get_string_id(candidate_name + name_offset,(char *)0x0);
                  if (sym_version == candidate_id) {
                    return sym;
                  }
                }
                if ((uint)verdef_cursor[2] == 0) break;
                verdef_idx = verdef_idx + 1;
                verdef_cursor = (Elf64_Verdef *)((long)verdef_cursor + (ulong)(uint)verdef_cursor[2]);
              } while( TRUE );
            }
          }
        }
        chain_hash = *chain_entry;
        chain_entry = chain_entry + 1;
      } while ((chain_hash & 1) == 0);
    }
  }
  return (Elf64_Sym *)0x0;
}

