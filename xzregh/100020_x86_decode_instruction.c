// /home/kali/xzre-ghidra/xzregh/100020_x86_decode_instruction.c
// Function: x86_decode_instruction @ 0x100020
// Calling convention: __stdcall
// Prototype: BOOL __stdcall x86_decode_instruction(dasm_ctx_t * ctx, u8 * code_start, u8 * code_end)


/*
 * AutoDoc: Logs a secret-data breadcrumb, zeros the supplied `dasm_ctx_t`, and decodes sequentially from `code_start`, handling legacy lock/REP prefixes, REX, and the two- and three-byte VEX encodings alongside ModRM/SIB and displacement/immediate operands. Prefix bookkeeping populates `ctx->opcode_window`, `opcode_offset`, `mem_disp`, and the signed/zero-extended immediates so MOV/LEA scanners can interrogate the context without re-running the decoder. Any invalid opcode, truncated buffer, or inconsistent prefix clears the context and returns FALSE so callers can advance one byte and retry; clean decodes leave `ctx->instruction`/`instruction_size` describing the instruction that was just observed.
 */

#include "xzre_types.h"

BOOL x86_decode_instruction(dasm_ctx_t *ctx,u8 *code_start,u8 *code_end)

{
  u8 *flags2_ptr;
  byte cursor_byte;
  byte modrm_byte;
  ushort imm16_word;
  byte tmp_byte;
  BOOL telemetry_ok;
  int derived_opcode;
  u64 imm_field;
  sbyte opcode_index;
  uint opcode;
  uint opcode_high_bits;
  long clear_idx;
  u8 *cursor;
  u8 *opcode_ptr;
  byte current_byte;
  uint normalized_opcode;
  ulong opcode_class_mask;
  ulong opcode_class_entry;
  u8 *imm_cursor;
  dasm_ctx_t *ctx_zero_cursor;
  ulong opcode_class_offset;
  x86_prefix_state_t *prefix_zero_cursor;
  BOOL predicate_ok;
  BOOL range_hits_upper_bound;
  byte ctx_zero_stride;
  ulong opcode_class_masks [4];
  
  ctx_zero_stride = 0;
  telemetry_ok = secret_data_append_bits_from_addr_or_ret
  // AutoDoc: Emit the breadcrumb before touching attacker-controlled bytes so later passes know a decode ran.
                    ((void *)0x0,(secret_data_shift_cursor_t)0x12,0x46,2);
  if (telemetry_ok == FALSE) {
    return FALSE;
  }
  ctx_zero_cursor = ctx;
  // AutoDoc: Clear every field in the decoder context so prefixes/immediates never leak between attempts.
  for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
    *(u32 *)&ctx_zero_cursor->instruction = 0;
    ctx_zero_cursor = (dasm_ctx_t *)((u8 *)ctx_zero_cursor + 4);
  }
  predicate_ok = code_start < code_end;
  cursor = code_start;
  do {
  // AutoDoc: Decode sequentially until the cursor falls off the buffer or we fail a predicate.
    if (!predicate_ok) {
LAB_00100aa5:
      for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
        *(u32 *)&ctx->instruction = 0;
        ctx = (dasm_ctx_t *)((u8 *)ctx + 4);
      }
      return FALSE;
    }
    current_byte = *cursor;
    if (current_byte < 0x68) {
      if (current_byte < 0x2e) {
        if (current_byte == 0xf) {
        // AutoDoc: 0x0F prefixes switch into the two-byte opcode table (with optional 0x38/0x3A extensions).
          *(u32 *)(ctx->opcode_window + 3) = 0xf;
          cursor = cursor + 1;
LAB_001001c9:
          if (code_end <= cursor) goto LAB_00100aa5;
          opcode = *(int *)(ctx->opcode_window + 3) << 8;
          *(uint *)(ctx->opcode_window + 3) = opcode;
          current_byte = *cursor;
          opcode = current_byte | opcode;
          *(uint *)(ctx->opcode_window + 3) = opcode;
          tmp_byte = *cursor;
          if ((tmp_byte & 0xfd) == 0x38) {
            if (((ctx->prefix).decoded.flags & 0x10) != 0) {
              return FALSE;
            }
            cursor = cursor + 1;
            goto LAB_001003fa;
          }
          if (((int)(uint)(byte)(&dasm_twobyte_is_valid)[tmp_byte >> 3] >> (tmp_byte & 7) & 1U) == 0) {
            return FALSE;
          }
          if (((ctx->prefix).decoded.lock_rep_byte == 0xf3) && (tmp_byte == 0x1e)) {
          // AutoDoc: Recognise ENDBR{32,64} quickly so the prologue walkers can bail early.
            if (cursor + 1 < code_end) {
              prefix_zero_cursor = &ctx->prefix;
              for (clear_idx = 0x12; clear_idx != 0; clear_idx = clear_idx + -1) {
                prefix_zero_cursor->flags_u32 = 0;
                prefix_zero_cursor = (x86_prefix_state_t *)((u8 *)prefix_zero_cursor + 4);
              }
              ctx->instruction = code_start;
              ctx->instruction_size = 4;
              derived_opcode = (cursor[1] == 0xfa) + 0xa5fc + (uint)(cursor[1] == 0xfa);
LAB_001004f1:
              *(int *)(ctx->opcode_window + 3) = derived_opcode;
              return TRUE;
            }
            goto LAB_00100aa5;
          }
          ctx->opcode_offset = (u8)((long)cursor - (long)code_start);
          normalized_opcode = opcode;
          if (((ctx->prefix).decoded.flags & 0x10) != 0) {
            normalized_opcode = (uint)current_byte;
          }
          if ((normalized_opcode & 0xf0) == 0x80) {
            imm_field = 4;
LAB_001004a7:
            flags2_ptr = &(ctx->prefix).decoded.flags2;
            *flags2_ptr = *flags2_ptr | 8;
            ctx->imm_size = imm_field;
          }
          else {
            if ((byte)normalized_opcode < 0x74) {
              if (0x6f < (normalized_opcode & 0xff)) {
LAB_001004a2:
                imm_field = 1;
                goto LAB_001004a7;
              }
            }
            else {
              opcode_high_bits = (normalized_opcode & 0xff) - 0xa4;
              if ((opcode_high_bits < 0x23) && ((0x740400101U >> ((byte)opcode_high_bits & 0x3f) & 1) != 0))
              goto LAB_001004a2;
            }
            ctx->imm_size = 0;
          }
          opcode_ptr = cursor;
          if (((byte)(&dasm_twobyte_has_modrm)[normalized_opcode >> 3 & 0x1f] >> (normalized_opcode & 7) & 1) == 0) {
            if (((ctx->prefix).decoded.flags2 & 8) != 0) goto LAB_0010067d;
            ctx->instruction = code_start;
            cursor = (byte *)(((long)cursor - (long)code_start) + 1);
          }
          else {
LAB_001008c5:
            cursor = opcode_ptr + 1;
            if (code_end <= cursor) goto LAB_00100aa5;
            current_byte = (ctx->prefix).decoded.flags;
            (ctx->prefix).decoded.flags = current_byte | 0x40;
            tmp_byte = *cursor;
            (ctx->prefix).modrm_bytes.modrm_byte = tmp_byte;
            // AutoDoc: Decode ModRM (MOD/REG/RM) and set DF2 flags so later displacement/SIB/immediate parsing knows what to consume.
            tmp_byte = tmp_byte >> 6;
            (ctx->prefix).modrm_bytes.modrm_mod = tmp_byte;
            cursor_byte = *cursor;
            (ctx->prefix).modrm_bytes.modrm_reg = (byte)((int)(uint)cursor_byte >> 3) & 7;
            modrm_byte = *cursor;
            (ctx->prefix).modrm_bytes.modrm_rm = modrm_byte & 7;
            if (tmp_byte == 3) {
LAB_00100902:
              if (((ctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000) {
LAB_0010092e:
                flags2_ptr = &(ctx->prefix).decoded.flags2;
                *flags2_ptr = *flags2_ptr | 1;
              }
            }
            else {
              if ((modrm_byte & 7) == 4) {
                (ctx->prefix).decoded.flags = current_byte | 0xc0;
              }
              if (tmp_byte != 1) {
                if (tmp_byte != 2) goto LAB_00100902;
                goto LAB_0010092e;
              }
              flags2_ptr = &(ctx->prefix).decoded.flags2;
              *flags2_ptr = *flags2_ptr | 3;
            }
            opcode = *(uint *)(ctx->opcode_window + 3);
            if ((opcode - 0xf6 < 2) && (((int)(uint)cursor_byte >> 3 & 7U) != 0)) {
              flags2_ptr = &(ctx->prefix).decoded.flags2;
              *flags2_ptr = *flags2_ptr & 0xf7;
              ctx->imm_size = 0;
            }
            if ((char)(ctx->prefix).decoded.flags < '\0') {
              if (code_end <= opcode_ptr + 2) goto LAB_00100aa5;
              current_byte = opcode_ptr[2];
              ctx->sib_byte = current_byte;
              ctx->sib_scale_bits = current_byte >> 6;
              ctx->sib_index_bits = (byte)((int)(uint)opcode_ptr[2] >> 3) & 7;
              current_byte = opcode_ptr[2];
              ctx->sib_base_bits = current_byte & 7;
              if ((current_byte & 7) == 5) {
                current_byte = (ctx->prefix).modrm_bytes.modrm_mod;
                if ((current_byte & 0xfd) == 0) {
                  flags2_ptr = &(ctx->prefix).decoded.flags2;
                  *flags2_ptr = *flags2_ptr | 1;
                }
                else if (current_byte == 1) {
                  flags2_ptr = &(ctx->prefix).decoded.flags2;
                  *flags2_ptr = *flags2_ptr | 3;
                }
              }
              current_byte = (ctx->prefix).decoded.flags2;
              if ((current_byte & 2) == 0) {
                if ((current_byte & 1) != 0) {
                  opcode_ptr = opcode_ptr + 3;
                  goto LAB_0010073c;
                }
                if ((current_byte & 8) != 0) {
                  cursor = opcode_ptr + 3;
                  goto LAB_00100680;
                }
                ctx->instruction = code_start;
                cursor = opcode_ptr + 2 + (1 - (long)code_start);
                goto LAB_001004e1;
              }
              cursor = opcode_ptr + 3;
LAB_001009ea:
              if (code_end <= cursor) goto LAB_00100aa5;
              current_byte = (ctx->prefix).decoded.flags2;
              ctx->mem_disp = (long)(char)*cursor;
            }
            else {
              current_byte = (ctx->prefix).decoded.flags2;
              if ((current_byte & 2) != 0) {
                cursor = opcode_ptr + 2;
                goto LAB_001009ea;
              }
              if ((current_byte & 1) != 0) goto LAB_0010065f;
            }
            if ((current_byte & 8) != 0) goto LAB_0010067d;
            ctx->instruction = code_start;
            cursor = cursor + (1 - (long)code_start);
          }
LAB_001004e1:
          ctx->instruction_size = (u64)cursor;
          if (cursor == (byte *)0x0) {
            return FALSE;
          }
          goto LAB_001004ee;
        }
        if (current_byte != 0x26) goto LAB_00100191;
      }
      else if ((0xc0000000010101U >> ((ulong)(current_byte - 0x2e) & 0x3f) & 1) == 0) {
        if (current_byte == 0x67) {
          current_byte = (ctx->prefix).decoded.flags;
          if ((current_byte & 8) != 0) {
            return FALSE;
          }
          (ctx->prefix).decoded.flags = current_byte | 8;
          (ctx->prefix).decoded.asize_byte = *cursor;
        }
        else {
          if (current_byte != 0x66) {
            if ((current_byte & 0xf0) == 0x40) {
              (ctx->prefix).decoded.flags = (ctx->prefix).decoded.flags | 0x20;
              current_byte = *cursor;
              cursor = cursor + 1;
              (ctx->prefix).modrm_bytes.rex_byte = current_byte;
            }
            goto LAB_00100191;
          }
          current_byte = (ctx->prefix).decoded.flags;
          if (((current_byte & 4) != 0) && ((ctx->prefix).decoded.osize_byte != 'f')) {
            return FALSE;
          }
          if ((current_byte & 0x20) == 0) {
            (ctx->prefix).decoded.flags = (ctx->prefix).decoded.flags | 4;
            (ctx->prefix).decoded.osize_byte = *cursor;
          }
        }
        goto LAB_00100675;
      }
      current_byte = (ctx->prefix).decoded.flags;
      if ((current_byte & 2) != 0) {
        return FALSE;
      }
      (ctx->prefix).decoded.flags = current_byte | 2;
      (ctx->prefix).decoded.seg_byte = *cursor;
    }
    else {
      if (current_byte != 0xf0) {
        if (current_byte < 0xf1) {
          if (1 < (byte)(current_byte + 0x3c)) goto LAB_00100191;
          tmp_byte = (ctx->prefix).decoded.flags;
          if ((tmp_byte & 0x20) != 0) {
            return FALSE;
          }
          *(uint *)(ctx->opcode_window + 3) = (uint)current_byte;
          cursor_byte = *cursor;
          opcode_ptr = cursor + 1;
          (ctx->prefix).decoded.flags = tmp_byte | 0x10;
          (ctx->prefix).decoded.vex_byte = cursor_byte;
          // AutoDoc: VEX prefix: capture the 0xC4/0xC5 header, synthesize REX bits/opcode-map selectors, and advance past the prefix bytes before decoding the opcode.
          if (code_end <= opcode_ptr) goto LAB_00100aa5;
          tmp_byte = cursor[1];
          (ctx->prefix).modrm_bytes.rex_byte = '@';
          opcode = (uint)current_byte << 8 | 0xf;
          (ctx->prefix).decoded.vex_byte2 = tmp_byte;
          *(uint *)(ctx->opcode_window + 3) = opcode;
          current_byte = ((char)cursor[1] >> 7 & 0xfcU) + 0x44;
          (ctx->prefix).modrm_bytes.rex_byte = current_byte;
          if (cursor_byte == 0xc5) goto LAB_001001c5;
          if (cursor_byte != 0xc4) {
            return FALSE;
          }
          cursor_byte = cursor[1];
          if ((cursor_byte & 0x40) == 0) {
            (ctx->prefix).modrm_bytes.rex_byte = current_byte | 2;
          }
          if ((cursor[1] & 0x20) == 0) {
            flags2_ptr = &(ctx->prefix).modrm_bytes.rex_byte;
            *flags2_ptr = *flags2_ptr | 1;
          }
          if (2 < (byte)((cursor_byte & 0x1f) - 1)) {
            return FALSE;
          }
          if (code_end <= cursor + 2) goto LAB_00100aa5;
          current_byte = cursor[2];
          tmp_byte = tmp_byte & 0x1f;
          (ctx->prefix).decoded.vex_byte3 = current_byte;
          if (-1 < (char)current_byte) {
            flags2_ptr = &(ctx->prefix).modrm_bytes.rex_byte;
            *flags2_ptr = *flags2_ptr | 8;
          }
          opcode = opcode << 8;
          *(uint *)(ctx->opcode_window + 3) = opcode;
          if (tmp_byte == 2) {
            opcode = opcode | 0x38;
          }
          else {
            if (tmp_byte != 3) {
              if (tmp_byte != 1) {
                return FALSE;
              }
              cursor = cursor + 3;
              goto LAB_001001c9;
            }
            opcode = opcode | 0x3a;
          }
          *(uint *)(ctx->opcode_window + 3) = opcode;
          cursor = cursor + 3;
LAB_001003fa:
          if (code_end <= cursor) goto LAB_00100aa5;
          opcode_high_bits = *(int *)(ctx->opcode_window + 3) << 8;
          *(uint *)(ctx->opcode_window + 3) = opcode_high_bits;
          current_byte = *cursor;
          opcode = current_byte | opcode_high_bits;
          *(uint *)(ctx->opcode_window + 3) = opcode;
          normalized_opcode = opcode;
          if (((ctx->prefix).decoded.flags & 0x10) != 0) {
            normalized_opcode = (uint)current_byte | opcode_high_bits & 0xffffff;
          }
          opcode_high_bits = normalized_opcode & 0xff00;
          opcode_ptr = cursor;
          if (opcode_high_bits != 0x3800) {
            opcode = normalized_opcode & 0xff;
            current_byte = (byte)normalized_opcode;
            if (current_byte < 0xf1) {
              if (opcode < 0xcc) {
                if (opcode < 0x3a) {
                  if (0x37 < opcode) goto LAB_001005bf;
                  predicate_ok = opcode - 0x20 < 2;
                  range_hits_upper_bound = opcode - 0x20 == 2;
                }
                else {
                  predicate_ok = opcode - 0x60 < 3;
                  range_hits_upper_bound = opcode - 0x60 == 3;
                }
                if (!predicate_ok && !range_hits_upper_bound) goto LAB_001005d6;
              }
              else if ((0x1000080001U >> (current_byte + 0x34 & 0x3f) & 1) == 0) goto LAB_001005d6;
LAB_001005bf:
              ctx->opcode_offset = (char)cursor - (char)code_start;
              if (opcode_high_bits == 0x3a00) {
LAB_0010063c:
                flags2_ptr = &(ctx->prefix).decoded.flags2;
                *flags2_ptr = *flags2_ptr | 8;
                ctx->imm_size = 1;
                goto LAB_001008c5;
              }
            }
            else {
LAB_001005d6:
              tmp_byte = current_byte & 0xf;
              if (current_byte >> 4 == 1) {
                if (tmp_byte < 10) {
                  predicate_ok = (normalized_opcode & 0xc) == 0;
                  goto LAB_00100604;
                }
                if (tmp_byte != 0xd) {
                  return FALSE;
                }
              }
              else {
                if (current_byte >> 4 == 4) {
                  predicate_ok = (0x1c57UL >> tmp_byte & 1) == 0;
                }
                else {
                  if (current_byte >> 4 != 0) {
                    return FALSE;
                  }
                  predicate_ok = (current_byte & 0xb) == 3;
                }
LAB_00100604:
                if (predicate_ok) {
                  return FALSE;
                }
              }
              ctx->opcode_offset = (char)cursor - (char)code_start;
              if ((opcode_high_bits == 0x3a00) && (2 < opcode - 0x4a)) goto LAB_0010063c;
            }
            ctx->imm_size = 0;
            goto LAB_001008c5;
          }
          opcode_high_bits = normalized_opcode >> 3 & 0x1f;
          if (((byte)(&dasm_threebyte_0x38_is_valid)[opcode_high_bits] >> (normalized_opcode & 7) & 1) == 0) {
            return FALSE;
          }
          ctx->imm_size = 0;
          current_byte = (&dasm_threebyte_has_modrm)[opcode_high_bits];
          ctx->opcode_offset = (u8)((long)cursor - (long)code_start);
          if ((current_byte >> (normalized_opcode & 7) & 1) != 0) goto LAB_001008c5;
          if (((ctx->prefix).decoded.flags2 & 8) == 0) {
            ctx->instruction = code_start;
            cursor = (byte *)(((long)cursor - (long)code_start) + 1);
            goto LAB_001004e1;
          }
LAB_0010067d:
          cursor = cursor + 1;
LAB_00100680:
          if (code_end <= cursor) goto LAB_00100aa5;
          imm_field = ctx->imm_size;
          current_byte = *cursor;
          if (imm_field != 1) {
            opcode_ptr = cursor + 1;
            if ((((ctx->prefix).decoded.flags & 4) != 0 && (ctx->prefix).decoded.osize_byte == 0x66)) {
            // AutoDoc: When an operand-size override is active (0x66 + DF2) flip 16- and 32-bit immediates so the decoded width stays accurate.
              if (imm_field == 2) {
                ctx->imm_size = 4;
              }
              else if (imm_field == 4) {
                ctx->imm_size = 2;
              }
            }
            if (code_end <= opcode_ptr) goto LAB_00100aa5;
            imm16_word = CONCAT11(*opcode_ptr,current_byte);
            if (ctx->imm_size == 2) {
              ctx->imm_zeroextended = (ulong)imm16_word;
              ctx->imm_signed = (long)(short)imm16_word;
              cursor = opcode_ptr + (1 - (long)code_start);
              ctx->instruction = code_start;
              goto LAB_001007e4;
            }
            if (code_end <= cursor + 2) goto LAB_00100aa5;
            imm_cursor = cursor + 3;
            if (code_end <= imm_cursor) goto LAB_00100aa5;
            opcode = CONCAT13(cursor[3],CONCAT12(cursor[2],imm16_word));
            if (ctx->imm_size == 4) {
              ctx->imm_zeroextended = (ulong)opcode;
              imm_field = (u64)(int)opcode;
            }
            else {
              if (((code_end <= cursor + 4) || (code_end <= cursor + 5)) ||
                 (code_end <= cursor + 6)) goto LAB_00100aa5;
              imm_cursor = cursor + 7;
              if (code_end <= imm_cursor) goto LAB_00100aa5;
              imm_field = CONCAT17(cursor[7],
                               CONCAT16(cursor[6],CONCAT15(cursor[5],CONCAT14(cursor[4],opcode)))
                              );
              ctx->imm_zeroextended = imm_field;
            }
            ctx->imm_signed = imm_field;
            goto LAB_0010089f;
          }
          ctx->imm_zeroextended = (ulong)current_byte;
          cursor = cursor + (1 - (long)code_start);
          ctx->imm_signed = (long)(char)current_byte;
          ctx->instruction = code_start;
          ctx->instruction_size = (u64)cursor;
        }
        else {
          if ((byte)(current_byte + 0xe) < 2) goto LAB_001000cf;
LAB_00100191:
          if (code_end <= cursor) goto LAB_00100aa5;
          current_byte = *cursor;
          opcode_class_offset = (ulong)current_byte;
          if (current_byte == 0xf) {
            *(u32 *)(ctx->opcode_window + 3) = 0xf;
            opcode_ptr = cursor;
LAB_001001c5:
            cursor = opcode_ptr + 1;
            goto LAB_001001c9;
          }
          opcode = (uint)current_byte;
          normalized_opcode = current_byte & 7;
          if (((byte)(&dasm_onebyte_is_invalid)[current_byte >> 3] >> normalized_opcode & 1) != 0) {
            return FALSE;
          }
          *(uint *)(ctx->opcode_window + 3) = (uint)current_byte;
          opcode_class_masks[0] = 0x3030303030303030;
          ctx->opcode_offset = (u8)((long)cursor - (long)code_start);
          opcode_class_masks[1] = 0xffff0fc000000000;
          opcode_class_masks[2] = 0xffff03000000000b;
          opcode_class_masks[3] = 0xc00bff000025c7;
          opcode_class_mask = opcode_class_masks[current_byte >> 6] >> (current_byte & 0x3f);
          opcode_class_entry = (ulong)((uint)opcode_class_mask & 1);
          if ((opcode_class_mask & 1) == 0) {
            ctx->imm_size = 0;
          }
          else {
            if (current_byte < 0xf8) {
              if (current_byte < 0xc2) {
                if (current_byte < 0x6a) {
                  if (current_byte < 0x2d) {
                    if (0x20 < (byte)(current_byte - 5)) goto LAB_00100344;
                    opcode_class_mask = 0x2020202020;
                  }
                  else {
                    opcode_class_mask = 0x1800000000010101;
                    opcode_class_offset = (ulong)(current_byte - 0x2d);
                  }
                }
                else {
                  opcode_class_mask = 0x7f80010000000001;
                  opcode_class_offset = (ulong)(current_byte + 0x7f);
                  if (0x3e < (byte)(current_byte + 0x7f)) goto LAB_00100344;
                }
                if ((opcode_class_mask >> (opcode_class_offset & 0x3f) & 1) != 0) {
                  opcode_class_entry = 4;
                }
              }
              else {
                opcode_class_offset = 1L << (current_byte + 0x3e & 0x3f);
                if ((opcode_class_offset & 0x2000c800000020) == 0) {
                  if ((opcode_class_offset & 0x101) != 0) {
                    opcode_class_entry = 2;
                  }
                }
                else {
                  opcode_class_entry = 4;
                }
              }
            }
LAB_00100344:
            flags2_ptr = &(ctx->prefix).decoded.flags2;
            *flags2_ptr = *flags2_ptr | 8;
            ctx->imm_size = opcode_class_entry;
          }
          opcode_index = (sbyte)normalized_opcode;
          opcode_ptr = cursor;
          if (((int)(uint)(byte)(&dasm_onebyte_has_modrm)[current_byte >> 3] >> opcode_index & 1U) != 0)
          goto LAB_001008c5;
          if (3 < current_byte - 0xa0) {
            tmp_byte = (ctx->prefix).decoded.flags2;
            if ((tmp_byte & 8) != 0) {
              if (((((ctx->prefix).decoded.flags & 0x20) != 0) &&
                  (((ctx->prefix).modrm_bytes.rex_byte & 8) != 0)) && ((current_byte & 0xf8) == 0xb8)) {
                ctx->imm_size = 8;
                (ctx->prefix).decoded.flags2 = tmp_byte | 0x10;
                ctx->mov_imm_reg_index = opcode_index;
                *(u32 *)(ctx->opcode_window + 3) = 0xb8;
              }
              goto LAB_0010067d;
            }
            ctx->instruction = code_start;
            cursor = (byte *)(((long)cursor - (long)code_start) + 1);
            goto LAB_001004e1;
          }
          flags2_ptr = &(ctx->prefix).decoded.flags2;
          *flags2_ptr = *flags2_ptr | 5;
LAB_0010065f:
          opcode_ptr = cursor + 1;
LAB_0010073c:
          if (((code_end <= opcode_ptr) || (code_end <= opcode_ptr + 1)) || (code_end <= opcode_ptr + 2))
          goto LAB_00100aa5;
          imm_cursor = opcode_ptr + 3;
          if (code_end <= imm_cursor) goto LAB_00100aa5;
          current_byte = (ctx->prefix).decoded.flags2;
          ctx->mem_disp =
               (long)CONCAT13(opcode_ptr[3],CONCAT12(opcode_ptr[2],CONCAT11(opcode_ptr[1],*opcode_ptr)));
          if ((current_byte & 4) == 0) {
            if ((current_byte & 8) != 0) {
              cursor = opcode_ptr + 4;
              goto LAB_00100680;
            }
LAB_0010089f:
            ctx->instruction = code_start;
            cursor = imm_cursor + (1 - (long)code_start);
          }
          else {
            if (((code_end <= opcode_ptr + 4) || (code_end <= opcode_ptr + 5)) ||
               ((code_end <= opcode_ptr + 6 || (code_end <= opcode_ptr + 7)))) goto LAB_00100aa5;
            if ((current_byte & 8) != 0) {
              cursor = opcode_ptr + 8;
              goto LAB_00100680;
            }
            ctx->instruction = code_start;
            cursor = opcode_ptr + 7 + (1 - (long)code_start);
          }
LAB_001007e4:
          ctx->instruction_size = (u64)cursor;
        }
        if (cursor == (byte *)0x0) {
          return FALSE;
        }
        opcode = *(uint *)(ctx->opcode_window + 3);
LAB_001004ee:
        derived_opcode = opcode + 0x80;
        goto LAB_001004f1;
      }
LAB_001000cf:
      current_byte = (ctx->prefix).decoded.flags;
      if ((current_byte & 1) != 0) {
        return FALSE;
      }
      (ctx->prefix).decoded.flags = current_byte | 1;
      (ctx->prefix).decoded.lock_rep_byte = *cursor;
    }
LAB_00100675:
    cursor = cursor + 1;
    predicate_ok = cursor < code_end;
  } while( TRUE );
}

