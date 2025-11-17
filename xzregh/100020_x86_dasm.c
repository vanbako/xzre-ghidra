// /home/kali/xzre-ghidra/xzregh/100020_x86_dasm.c
// Function: x86_dasm @ 0x100020
// Calling convention: __stdcall
// Prototype: BOOL __stdcall x86_dasm(dasm_ctx_t * ctx, u8 * code_start, u8 * code_end)


/*
 * AutoDoc: Resets the supplied `dasm_ctx_t` and incrementally decodes from `code_start`, honoring legacy prefixes, REX, 2- and 3-byte VEX, and ModRM/SIB so `opcode_window`, prefix bits, displacement/immediates, and the derived `operand`/`mem_disp` fields are normalised.
 * Invalid encodings or truncated buffers zero the context and return FALSE so callers can slide one byte and reattempt; a clean decode leaves `instruction`/`instruction_size` populated for upstream scanners like the MOV/LEA and prologue finders.
 */

#include "xzre_types.h"

BOOL x86_dasm(dasm_ctx_t *ctx,u8 *code_start,u8 *code_end)

{
  x86_rex_prefix_t *rex_prefix;
  u8 *flags2_ptr;
  byte bVar3;
  byte bVar4;
  ushort uVar5;
  byte bVar6;
  BOOL telemetry_ok;
  int derived_opcode;
  u64 operand_width;
  sbyte opcode_index;
  uint opcode;
  uint opcode_high_bits;
  long lVar13;
  u8 *cursor;
  u8 *opcode_ptr;
  byte current_byte;
  uint normalized_opcode;
  ulong opcode_class_mask;
  ulong opcode_class_flag;
  u8 *operand_cursor;
  dasm_ctx_t *ctx_clear;
  ulong uVar22;
  x86_prefix_state_t *prefix_clear;
  BOOL bVar24;
  BOOL bVar25;
  byte bVar26;
  ulong opcode_class_masks [4];
  
  bVar26 = 0;
  telemetry_ok = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x12,0x46,2);
  if (telemetry_ok == FALSE) {
    return FALSE;
  }
  ctx_clear = ctx;
  for (lVar13 = 0x16; lVar13 != 0; lVar13 = lVar13 + -1) {
    *(undefined4 *)&ctx_clear->instruction = 0;
    ctx_clear = (dasm_ctx_t *)((long)ctx_clear + (ulong)bVar26 * -8 + 4);
  }
  bVar24 = code_start < code_end;
  cursor = code_start;
  do {
    if (!bVar24) {
LAB_00100aa5:
      for (lVar13 = 0x16; lVar13 != 0; lVar13 = lVar13 + -1) {
        *(undefined4 *)&ctx->instruction = 0;
        ctx = (dasm_ctx_t *)((long)ctx + (ulong)bVar26 * -8 + 4);
      }
      return FALSE;
    }
    current_byte = *cursor;
    if (current_byte < 0x68) {
      if (current_byte < 0x2e) {
        if (current_byte == 0xf) {
          *(undefined4 *)(ctx->opcode_window + 3) = 0xf;
          cursor = cursor + 1;
LAB_001001c9:
          if (code_end <= cursor) goto LAB_00100aa5;
          opcode = *(int *)(ctx->opcode_window + 3) << 8;
          *(uint *)(ctx->opcode_window + 3) = opcode;
          current_byte = *cursor;
          opcode = current_byte | opcode;
          *(uint *)(ctx->opcode_window + 3) = opcode;
          bVar6 = *cursor;
          if ((bVar6 & 0xfd) == 0x38) {
            if (((ctx->prefix).decoded.flags & 0x10) != 0) {
              return FALSE;
            }
            cursor = cursor + 1;
            goto LAB_001003fa;
          }
          if (((int)(uint)(byte)(&dasm_twobyte_is_valid)[bVar6 >> 3] >> (bVar6 & 7) & 1U) == 0) {
            return FALSE;
          }
          if (((ctx->prefix).decoded.lock_rep_byte == 0xf3) && (bVar6 == 0x1e)) {
            if (cursor + 1 < code_end) {
              prefix_clear = &ctx->prefix;
              for (lVar13 = 0x12; lVar13 != 0; lVar13 = lVar13 + -1) {
                *(undefined4 *)prefix_clear = 0;
                prefix_clear = (x86_prefix_state_t *)((long)prefix_clear + (ulong)bVar26 * -8 + 4);
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
          ctx->insn_offset = (u8)((long)cursor - (long)code_start);
          normalized_opcode = opcode;
          if (((ctx->prefix).decoded.flags & 0x10) != 0) {
            normalized_opcode = (uint)current_byte;
          }
          if ((normalized_opcode & 0xf0) == 0x80) {
            operand_width = 4;
LAB_001004a7:
            flags2_ptr = &(ctx->prefix).decoded.flags2;
            *flags2_ptr = *flags2_ptr | 8;
            ctx->operand_size = operand_width;
          }
          else {
            if ((byte)normalized_opcode < 0x74) {
              if (0x6f < (normalized_opcode & 0xff)) {
LAB_001004a2:
                operand_width = 1;
                goto LAB_001004a7;
              }
            }
            else {
              opcode_high_bits = (normalized_opcode & 0xff) - 0xa4;
              if ((opcode_high_bits < 0x23) && ((0x740400101U >> ((byte)opcode_high_bits & 0x3f) & 1) != 0))
              goto LAB_001004a2;
            }
            ctx->operand_size = 0;
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
            bVar6 = *cursor;
            *(byte *)((long)&ctx->prefix + 0xc) = bVar6;
            bVar6 = bVar6 >> 6;
            *(byte *)((long)&ctx->prefix + 0xd) = bVar6;
            bVar3 = *cursor;
            *(byte *)((long)&ctx->prefix + 0xe) = (byte)((int)(uint)bVar3 >> 3) & 7;
            bVar4 = *cursor;
            *(byte *)((long)&ctx->prefix + 0xf) = bVar4 & 7;
            if (bVar6 == 3) {
LAB_00100902:
              if (((ctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000) {
LAB_0010092e:
                flags2_ptr = &(ctx->prefix).decoded.flags2;
                *flags2_ptr = *flags2_ptr | 1;
              }
            }
            else {
              if ((bVar4 & 7) == 4) {
                (ctx->prefix).decoded.flags = current_byte | 0xc0;
              }
              if (bVar6 != 1) {
                if (bVar6 != 2) goto LAB_00100902;
                goto LAB_0010092e;
              }
              flags2_ptr = &(ctx->prefix).decoded.flags2;
              *flags2_ptr = *flags2_ptr | 3;
            }
            opcode = *(uint *)(ctx->opcode_window + 3);
            if ((opcode - 0xf6 < 2) && (((int)(uint)bVar3 >> 3 & 7U) != 0)) {
              flags2_ptr = &(ctx->prefix).decoded.flags2;
              *flags2_ptr = *flags2_ptr & 0xf7;
              ctx->operand_size = 0;
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
                current_byte = *(byte *)((long)&ctx->prefix + 0xd);
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
              (ctx->prefix).decoded.rex.rex_byte = current_byte;
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
          bVar6 = (ctx->prefix).decoded.flags;
          if ((bVar6 & 0x20) != 0) {
            return FALSE;
          }
          *(uint *)(ctx->opcode_window + 3) = (uint)current_byte;
          bVar3 = *cursor;
          opcode_ptr = cursor + 1;
          (ctx->prefix).decoded.flags = bVar6 | 0x10;
          (ctx->prefix).decoded.vex_byte = bVar3;
          if (code_end <= opcode_ptr) goto LAB_00100aa5;
          bVar6 = cursor[1];
          (ctx->prefix).decoded.rex.rex_byte = '@';
          opcode = (uint)current_byte << 8 | 0xf;
          (ctx->prefix).decoded.vex_byte2 = bVar6;
          *(uint *)(ctx->opcode_window + 3) = opcode;
          current_byte = ((char)cursor[1] >> 7 & 0xfcU) + 0x44;
          *(byte *)((long)&ctx->prefix + 0xb) = current_byte;
          if (bVar3 == 0xc5) goto LAB_001001c5;
          if (bVar3 != 0xc4) {
            return FALSE;
          }
          bVar3 = cursor[1];
          if ((bVar3 & 0x40) == 0) {
            (ctx->prefix).decoded.rex.rex_byte = current_byte | 2;
          }
          if ((cursor[1] & 0x20) == 0) {
            rex_prefix = &(ctx->prefix).decoded.rex;
            rex_prefix->rex_byte = rex_prefix->rex_byte | 1;
          }
          if (2 < (byte)((bVar3 & 0x1f) - 1)) {
            return FALSE;
          }
          if (code_end <= cursor + 2) goto LAB_00100aa5;
          current_byte = cursor[2];
          bVar6 = bVar6 & 0x1f;
          (ctx->prefix).decoded.vex_byte3 = current_byte;
          if (-1 < (char)current_byte) {
            rex_prefix = &(ctx->prefix).decoded.rex;
            rex_prefix->rex_byte = rex_prefix->rex_byte | 8;
          }
          opcode = opcode << 8;
          *(uint *)(ctx->opcode_window + 3) = opcode;
          if (bVar6 == 2) {
            opcode = opcode | 0x38;
          }
          else {
            if (bVar6 != 3) {
              if (bVar6 != 1) {
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
                  bVar24 = opcode - 0x20 < 2;
                  bVar25 = opcode - 0x20 == 2;
                }
                else {
                  bVar24 = opcode - 0x60 < 3;
                  bVar25 = opcode - 0x60 == 3;
                }
                if (!bVar24 && !bVar25) goto LAB_001005d6;
              }
              else if ((0x1000080001U >> (current_byte + 0x34 & 0x3f) & 1) == 0) goto LAB_001005d6;
LAB_001005bf:
              ctx->insn_offset = (char)cursor - (char)code_start;
              if (opcode_high_bits == 0x3a00) {
LAB_0010063c:
                flags2_ptr = &(ctx->prefix).decoded.flags2;
                *flags2_ptr = *flags2_ptr | 8;
                ctx->operand_size = 1;
                goto LAB_001008c5;
              }
            }
            else {
LAB_001005d6:
              bVar6 = current_byte & 0xf;
              if (current_byte >> 4 == 1) {
                if (bVar6 < 10) {
                  bVar24 = (normalized_opcode & 0xc) == 0;
                  goto LAB_00100604;
                }
                if (bVar6 != 0xd) {
                  return FALSE;
                }
              }
              else {
                if (current_byte >> 4 == 4) {
                  bVar24 = (0x1c57UL >> bVar6 & 1) == 0;
                }
                else {
                  if (current_byte >> 4 != 0) {
                    return FALSE;
                  }
                  bVar24 = (current_byte & 0xb) == 3;
                }
LAB_00100604:
                if (bVar24) {
                  return FALSE;
                }
              }
              ctx->insn_offset = (char)cursor - (char)code_start;
              if ((opcode_high_bits == 0x3a00) && (2 < opcode - 0x4a)) goto LAB_0010063c;
            }
            ctx->operand_size = 0;
            goto LAB_001008c5;
          }
          opcode_high_bits = normalized_opcode >> 3 & 0x1f;
          if (((byte)(&dasm_threebyte_0x38_is_valid)[opcode_high_bits] >> (normalized_opcode & 7) & 1) == 0) {
            return FALSE;
          }
          ctx->operand_size = 0;
          current_byte = (&dasm_threebyte_has_modrm)[opcode_high_bits];
          ctx->insn_offset = (u8)((long)cursor - (long)code_start);
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
          operand_width = ctx->operand_size;
          current_byte = *cursor;
          if (operand_width != 1) {
            opcode_ptr = cursor + 1;
            if (((undefined1  [16])ctx->prefix & (undefined1  [16])0xff000000000004) ==
                (undefined1  [16])0x66000000000004) {
              if (operand_width == 2) {
                ctx->operand_size = 4;
              }
              else if (operand_width == 4) {
                ctx->operand_size = 2;
              }
            }
            if (code_end <= opcode_ptr) goto LAB_00100aa5;
            uVar5 = CONCAT11(*opcode_ptr,current_byte);
            if (ctx->operand_size == 2) {
              ctx->operand_zeroextended = (ulong)uVar5;
              ctx->operand = (long)(short)uVar5;
              cursor = opcode_ptr + (1 - (long)code_start);
              ctx->instruction = code_start;
              goto LAB_001007e4;
            }
            if (code_end <= cursor + 2) goto LAB_00100aa5;
            operand_cursor = cursor + 3;
            if (code_end <= operand_cursor) goto LAB_00100aa5;
            opcode = CONCAT13(cursor[3],CONCAT12(cursor[2],uVar5));
            if (ctx->operand_size == 4) {
              ctx->operand_zeroextended = (ulong)opcode;
              operand_width = (u64)(int)opcode;
            }
            else {
              if (((code_end <= cursor + 4) || (code_end <= cursor + 5)) ||
                 (code_end <= cursor + 6)) goto LAB_00100aa5;
              operand_cursor = cursor + 7;
              if (code_end <= operand_cursor) goto LAB_00100aa5;
              operand_width = CONCAT17(cursor[7],
                               CONCAT16(cursor[6],CONCAT15(cursor[5],CONCAT14(cursor[4],opcode)))
                              );
              ctx->operand_zeroextended = operand_width;
            }
            ctx->operand = operand_width;
            goto LAB_0010089f;
          }
          ctx->operand_zeroextended = (ulong)current_byte;
          cursor = cursor + (1 - (long)code_start);
          ctx->operand = (long)(char)current_byte;
          ctx->instruction = code_start;
          ctx->instruction_size = (u64)cursor;
        }
        else {
          if ((byte)(current_byte + 0xe) < 2) goto LAB_001000cf;
LAB_00100191:
          if (code_end <= cursor) goto LAB_00100aa5;
          current_byte = *cursor;
          uVar22 = (ulong)current_byte;
          if (current_byte == 0xf) {
            *(undefined4 *)(ctx->opcode_window + 3) = 0xf;
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
          ctx->insn_offset = (u8)((long)cursor - (long)code_start);
          opcode_class_masks[1] = 0xffff0fc000000000;
          opcode_class_masks[2] = 0xffff03000000000b;
          opcode_class_masks[3] = 0xc00bff000025c7;
          opcode_class_mask = opcode_class_masks[current_byte >> 6] >> (current_byte & 0x3f);
          opcode_class_flag = (ulong)((uint)opcode_class_mask & 1);
          if ((opcode_class_mask & 1) == 0) {
            ctx->operand_size = 0;
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
                    uVar22 = (ulong)(current_byte - 0x2d);
                  }
                }
                else {
                  opcode_class_mask = 0x7f80010000000001;
                  uVar22 = (ulong)(current_byte + 0x7f);
                  if (0x3e < (byte)(current_byte + 0x7f)) goto LAB_00100344;
                }
                if ((opcode_class_mask >> (uVar22 & 0x3f) & 1) != 0) {
                  opcode_class_flag = 4;
                }
              }
              else {
                uVar22 = 1L << (current_byte + 0x3e & 0x3f);
                if ((uVar22 & 0x2000c800000020) == 0) {
                  if ((uVar22 & 0x101) != 0) {
                    opcode_class_flag = 2;
                  }
                }
                else {
                  opcode_class_flag = 4;
                }
              }
            }
LAB_00100344:
            flags2_ptr = &(ctx->prefix).decoded.flags2;
            *flags2_ptr = *flags2_ptr | 8;
            ctx->operand_size = opcode_class_flag;
          }
          opcode_index = (sbyte)normalized_opcode;
          opcode_ptr = cursor;
          if (((int)(uint)(byte)(&dasm_onebyte_has_modrm)[current_byte >> 3] >> opcode_index & 1U) != 0)
          goto LAB_001008c5;
          if (3 < current_byte - 0xa0) {
            bVar6 = (ctx->prefix).decoded.flags2;
            if ((bVar6 & 8) != 0) {
              if (((((ctx->prefix).decoded.flags & 0x20) != 0) &&
                  (((ctx->prefix).decoded.rex.rex_byte & 8) != 0)) && ((current_byte & 0xf8) == 0xb8)) {
                ctx->operand_size = 8;
                (ctx->prefix).decoded.flags2 = bVar6 | 0x10;
                ctx->imm64_reg = opcode_index;
                *(undefined4 *)(ctx->opcode_window + 3) = 0xb8;
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
          operand_cursor = opcode_ptr + 3;
          if (code_end <= operand_cursor) goto LAB_00100aa5;
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
            cursor = operand_cursor + (1 - (long)code_start);
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
    bVar24 = cursor < code_end;
  } while( TRUE );
}

