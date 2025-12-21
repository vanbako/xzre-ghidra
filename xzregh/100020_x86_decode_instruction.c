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
  dasm_opcode_window_t vex_prefix_window;
  dasm_opcode_window_t opcode_window_seed;
  u32 derived_opcode;
  sbyte sVar10;
  X86_OPCODE XVar11;
  X86_OPCODE XVar12;
  long lVar13;
  byte *pbVar14;
  u8 *cursor;
  byte bVar16;
  X86_OPCODE XVar17;
  ulong opcode_class_entry;
  ulong opcode_class_mask;
  byte *pbVar20;
  uint uVar21;
  dasm_ctx_t *ctx_zero_cursor;
  ulong opcode_class_offset;
  x86_prefix_state_t *prefix_zero_cursor;
  byte ctx_zero_stride;
  BOOL range_hits_upper_bound;
  byte zero_stride_flag;
  ulong opcode_class_masks [4];
  
  zero_stride_flag = 0;
  telemetry_ok = secret_data_append_bits_from_addr_or_ret
  // AutoDoc: Emit the breadcrumb before touching attacker-controlled bytes so later passes know a decode ran.
                    ((void *)0x0,(secret_data_shift_cursor_t)0x12,0x46,2);
  if (telemetry_ok == FALSE) {
    return FALSE;
  }
  ctx_zero_cursor = ctx;
  // AutoDoc: Clear every field in the decoder context so prefixes/immediates never leak between attempts.
  for (lVar13 = 0x16; lVar13 != 0; lVar13 = lVar13 + -1) {
    *(u32 *)&ctx_zero_cursor->instruction = 0;
    ctx_zero_cursor = (dasm_ctx_t *)((u8 *)ctx_zero_cursor + 4);
  }
  ctx_zero_stride = code_start < code_end;
  pbVar14 = code_start;
  do {
  // AutoDoc: Decode sequentially until the cursor falls off the buffer or we fail a predicate.
    if (!ctx_zero_stride) {
LAB_00100aa5:
      for (lVar13 = 0x16; lVar13 != 0; lVar13 = lVar13 + -1) {
        *(u32 *)&ctx->instruction = 0;
        ctx = (dasm_ctx_t *)((u8 *)ctx + 4);
      }
      return FALSE;
    }
    bVar16 = *pbVar14;
    vex_prefix_window.opcode_window_dword._1_3_ = 0;
    vex_prefix_window.opcode_window[0] = bVar16;
    if (bVar16 < 0x68) {
      if (bVar16 < 0x2e) {
        if (bVar16 == 0xf) {
        // AutoDoc: 0x0F prefixes switch into the two-byte opcode table (with optional 0x38/0x3A extensions).
          (ctx->opcode_window).opcode_window_dword = 0xf;
          pbVar14 = pbVar14 + 1;
LAB_001001c9:
          if (code_end <= pbVar14) goto LAB_00100aa5;
          XVar11 = (ctx->opcode_window).opcode_window_dword << 8;
          (ctx->opcode_window).opcode_window_dword = XVar11;
          bVar16 = *pbVar14;
          XVar11 = bVar16 | XVar11;
          (ctx->opcode_window).opcode_window_dword = XVar11;
          tmp_byte = *pbVar14;
          if ((tmp_byte & 0xfd) == 0x38) {
            if (((ctx->prefix).decoded.flags & 0x10) != 0) {
              return FALSE;
            }
            pbVar14 = pbVar14 + 1;
            goto LAB_001003fa;
          }
          if (((int)(uint)(byte)(&dasm_twobyte_is_valid)[tmp_byte >> 3] >> (tmp_byte & 7) & 1U) == 0) {
            return FALSE;
          }
          if (((ctx->prefix).decoded.lock_rep_byte == 0xf3) && (tmp_byte == 0x1e)) {
          // AutoDoc: Recognise ENDBR{32,64} quickly so the prologue walkers can bail early.
            if (pbVar14 + 1 < code_end) {
              prefix_zero_cursor = &ctx->prefix;
              for (lVar13 = 0x12; lVar13 != 0; lVar13 = lVar13 + -1) {
                prefix_zero_cursor->flags_u32 = 0;
                prefix_zero_cursor = (x86_prefix_state_t *)((u8 *)prefix_zero_cursor + 4);
              }
              ctx->instruction = code_start;
              ctx->instruction_size = 4;
              XVar11 = (pbVar14[1] == 0xfa) + 0xa5fc + (uint)(pbVar14[1] == 0xfa);
LAB_001004f1:
              (ctx->opcode_window).opcode_window_dword = XVar11;
              return TRUE;
            }
            goto LAB_00100aa5;
          }
          ctx->opcode_offset = (u8)((long)pbVar14 - (long)code_start);
          XVar17 = XVar11;
          if (((ctx->prefix).decoded.flags & 0x10) != 0) {
            XVar17 = (uint)bVar16;
          }
          if ((XVar17 & 0xf0) == 0x80) {
            derived_opcode = 4;
LAB_001004a7:
            flags2_ptr = &(ctx->prefix).decoded.flags2;
            *flags2_ptr = *flags2_ptr | 8;
            ctx->imm_size = derived_opcode;
          }
          else {
            if ((byte)XVar17 < 0x74) {
              if (0x6f < (XVar17 & 0xff)) {
LAB_001004a2:
                derived_opcode = 1;
                goto LAB_001004a7;
              }
            }
            else {
              uVar21 = (XVar17 & 0xff) - 0xa4;
              if ((uVar21 < 0x23) && ((0x740400101U >> ((byte)uVar21 & 0x3f) & 1) != 0))
              goto LAB_001004a2;
            }
            ctx->imm_size = 0;
          }
          cursor = pbVar14;
          if (((byte)(&dasm_twobyte_has_modrm)[XVar17 >> 3 & 0x1f] >> (XVar17 & 7) & 1) == 0) {
            if (((ctx->prefix).decoded.flags2 & 8) != 0) goto LAB_0010067d;
            ctx->instruction = code_start;
            pbVar14 = (byte *)(((long)pbVar14 - (long)code_start) + 1);
          }
          else {
LAB_001008c5:
            pbVar14 = cursor + 1;
            if (code_end <= pbVar14) goto LAB_00100aa5;
            bVar16 = (ctx->prefix).decoded.flags;
            (ctx->prefix).decoded.flags = bVar16 | 0x40;
            tmp_byte = *pbVar14;
            (ctx->prefix).modrm_bytes.modrm_byte = tmp_byte;
            // AutoDoc: Decode ModRM (MOD/REG/RM) and set DF2 flags so later displacement/SIB/immediate parsing knows what to consume.
            tmp_byte = tmp_byte >> 6;
            (ctx->prefix).modrm_bytes.modrm_mod = tmp_byte;
            cursor_byte = *pbVar14;
            (ctx->prefix).modrm_bytes.modrm_reg = (byte)((int)(uint)cursor_byte >> 3) & 7;
            modrm_byte = *pbVar14;
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
                (ctx->prefix).decoded.flags = bVar16 | 0xc0;
              }
              if (tmp_byte != 1) {
                if (tmp_byte != 2) goto LAB_00100902;
                goto LAB_0010092e;
              }
              flags2_ptr = &(ctx->prefix).decoded.flags2;
              *flags2_ptr = *flags2_ptr | 3;
            }
            XVar11 = (ctx->opcode_window).opcode_window_dword;
            if ((XVar11 - 0xf6 < 2) && (((int)(uint)cursor_byte >> 3 & 7U) != 0)) {
              flags2_ptr = &(ctx->prefix).decoded.flags2;
              *flags2_ptr = *flags2_ptr & 0xf7;
              ctx->imm_size = 0;
            }
            if ((char)(ctx->prefix).decoded.flags < '\0') {
              if (code_end <= cursor + 2) goto LAB_00100aa5;
              bVar16 = cursor[2];
              ctx->sib_byte = bVar16;
              ctx->sib_scale_bits = bVar16 >> 6;
              ctx->sib_index_bits = (byte)((int)(uint)cursor[2] >> 3) & 7;
              bVar16 = cursor[2];
              ctx->sib_base_bits = bVar16 & 7;
              if ((bVar16 & 7) == 5) {
                bVar16 = (ctx->prefix).modrm_bytes.modrm_mod;
                if ((bVar16 & 0xfd) == 0) {
                  flags2_ptr = &(ctx->prefix).decoded.flags2;
                  *flags2_ptr = *flags2_ptr | 1;
                }
                else if (bVar16 == 1) {
                  flags2_ptr = &(ctx->prefix).decoded.flags2;
                  *flags2_ptr = *flags2_ptr | 3;
                }
              }
              bVar16 = (ctx->prefix).decoded.flags2;
              if ((bVar16 & 2) == 0) {
                if ((bVar16 & 1) != 0) {
                  cursor = cursor + 3;
                  goto LAB_0010073c;
                }
                if ((bVar16 & 8) != 0) {
                  pbVar14 = cursor + 3;
                  goto LAB_00100680;
                }
                ctx->instruction = code_start;
                pbVar14 = cursor + 2 + (1 - (long)code_start);
                goto LAB_001004e1;
              }
              pbVar14 = cursor + 3;
LAB_001009ea:
              if (code_end <= pbVar14) goto LAB_00100aa5;
              bVar16 = (ctx->prefix).decoded.flags2;
              ctx->mem_disp = (long)(char)*pbVar14;
            }
            else {
              bVar16 = (ctx->prefix).decoded.flags2;
              if ((bVar16 & 2) != 0) {
                pbVar14 = cursor + 2;
                goto LAB_001009ea;
              }
              if ((bVar16 & 1) != 0) goto LAB_0010065f;
            }
            if ((bVar16 & 8) != 0) goto LAB_0010067d;
            ctx->instruction = code_start;
            pbVar14 = pbVar14 + (1 - (long)code_start);
          }
LAB_001004e1:
          ctx->instruction_size = (u64)pbVar14;
          if (pbVar14 == (byte *)0x0) {
            return FALSE;
          }
          goto LAB_001004ee;
        }
        if (bVar16 != 0x26) goto LAB_00100191;
      }
      else if ((0xc0000000010101U >> ((ulong)(bVar16 - 0x2e) & 0x3f) & 1) == 0) {
        if (bVar16 == 0x67) {
          bVar16 = (ctx->prefix).decoded.flags;
          if ((bVar16 & 8) != 0) {
            return FALSE;
          }
          (ctx->prefix).decoded.flags = bVar16 | 8;
          (ctx->prefix).decoded.asize_byte = *pbVar14;
        }
        else {
          if (bVar16 != 0x66) {
            if ((bVar16 & 0xf0) == 0x40) {
              (ctx->prefix).decoded.flags = (ctx->prefix).decoded.flags | 0x20;
              bVar16 = *pbVar14;
              pbVar14 = pbVar14 + 1;
              (ctx->prefix).modrm_bytes.rex_byte = bVar16;
            }
            goto LAB_00100191;
          }
          bVar16 = (ctx->prefix).decoded.flags;
          if (((bVar16 & 4) != 0) && ((ctx->prefix).decoded.osize_byte != 'f')) {
            return FALSE;
          }
          if ((bVar16 & 0x20) == 0) {
            (ctx->prefix).decoded.flags = (ctx->prefix).decoded.flags | 4;
            (ctx->prefix).decoded.osize_byte = *pbVar14;
          }
        }
        goto LAB_00100675;
      }
      bVar16 = (ctx->prefix).decoded.flags;
      if ((bVar16 & 2) != 0) {
        return FALSE;
      }
      (ctx->prefix).decoded.flags = bVar16 | 2;
      (ctx->prefix).decoded.seg_byte = *pbVar14;
    }
    else {
      if (bVar16 != 0xf0) {
        if (bVar16 < 0xf1) {
          if (1 < (byte)(bVar16 + 0x3c)) goto LAB_00100191;
          tmp_byte = (ctx->prefix).decoded.flags;
          if ((tmp_byte & 0x20) != 0) {
            return FALSE;
          }
          ctx->opcode_window = vex_prefix_window;
          cursor_byte = *pbVar14;
          cursor = pbVar14 + 1;
          (ctx->prefix).decoded.flags = tmp_byte | 0x10;
          (ctx->prefix).decoded.vex_byte = cursor_byte;
          // AutoDoc: VEX prefix: capture the 0xC4/0xC5 header, synthesize REX bits/opcode-map selectors, and advance past the prefix bytes before decoding the opcode.
          if (code_end <= cursor) goto LAB_00100aa5;
          tmp_byte = pbVar14[1];
          (ctx->prefix).modrm_bytes.rex_byte = '@';
          XVar11 = (uint)bVar16 << 8 | 0xf;
          (ctx->prefix).decoded.vex_byte2 = tmp_byte;
          (ctx->opcode_window).opcode_window_dword = XVar11;
          bVar16 = ((char)pbVar14[1] >> 7 & 0xfcU) + 0x44;
          (ctx->prefix).modrm_bytes.rex_byte = bVar16;
          if (cursor_byte == 0xc5) goto LAB_001001c5;
          if (cursor_byte != 0xc4) {
            return FALSE;
          }
          cursor_byte = pbVar14[1];
          if ((cursor_byte & 0x40) == 0) {
            (ctx->prefix).modrm_bytes.rex_byte = bVar16 | 2;
          }
          if ((pbVar14[1] & 0x20) == 0) {
            flags2_ptr = &(ctx->prefix).modrm_bytes.rex_byte;
            *flags2_ptr = *flags2_ptr | 1;
          }
          if (2 < (byte)((cursor_byte & 0x1f) - 1)) {
            return FALSE;
          }
          if (code_end <= pbVar14 + 2) goto LAB_00100aa5;
          bVar16 = pbVar14[2];
          tmp_byte = tmp_byte & 0x1f;
          (ctx->prefix).decoded.vex_byte3 = bVar16;
          if (-1 < (char)bVar16) {
            flags2_ptr = &(ctx->prefix).modrm_bytes.rex_byte;
            *flags2_ptr = *flags2_ptr | 8;
          }
          XVar11 = XVar11 << 8;
          (ctx->opcode_window).opcode_window_dword = XVar11;
          if (tmp_byte == 2) {
            XVar11 = XVar11 | 0x38;
          }
          else {
            if (tmp_byte != 3) {
              if (tmp_byte != 1) {
                return FALSE;
              }
              pbVar14 = pbVar14 + 3;
              goto LAB_001001c9;
            }
            XVar11 = XVar11 | 0x3a;
          }
          (ctx->opcode_window).opcode_window_dword = XVar11;
          pbVar14 = pbVar14 + 3;
LAB_001003fa:
          if (code_end <= pbVar14) goto LAB_00100aa5;
          XVar12 = (ctx->opcode_window).opcode_window_dword << 8;
          (ctx->opcode_window).opcode_window_dword = XVar12;
          bVar16 = *pbVar14;
          XVar11 = bVar16 | XVar12;
          (ctx->opcode_window).opcode_window_dword = XVar11;
          XVar17 = XVar11;
          if (((ctx->prefix).decoded.flags & 0x10) != 0) {
            XVar17 = (uint)bVar16 | XVar12 & 0xffffff;
          }
          XVar12 = XVar17 & 0xff00;
          cursor = pbVar14;
          if (XVar12 != 0x3800) {
            XVar11 = XVar17 & 0xff;
            bVar16 = (byte)XVar17;
            if (bVar16 < 0xf1) {
              if (XVar11 < 0xcc) {
                if (XVar11 < 0x3a) {
                  if (0x37 < XVar11) goto LAB_001005bf;
                  ctx_zero_stride = XVar11 - 0x20 < 2;
                  range_hits_upper_bound = XVar11 - 0x20 == 2;
                }
                else {
                  ctx_zero_stride = XVar11 - 0x60 < 3;
                  range_hits_upper_bound = XVar11 - 0x60 == 3;
                }
                if (!ctx_zero_stride && !range_hits_upper_bound) goto LAB_001005d6;
              }
              else if ((0x1000080001U >> (bVar16 + 0x34 & 0x3f) & 1) == 0) goto LAB_001005d6;
LAB_001005bf:
              ctx->opcode_offset = (char)pbVar14 - (char)code_start;
              if (XVar12 == 0x3a00) {
LAB_0010063c:
                flags2_ptr = &(ctx->prefix).decoded.flags2;
                *flags2_ptr = *flags2_ptr | 8;
                ctx->imm_size = 1;
                goto LAB_001008c5;
              }
            }
            else {
LAB_001005d6:
              tmp_byte = bVar16 & 0xf;
              if (bVar16 >> 4 == 1) {
                if (tmp_byte < 10) {
                  ctx_zero_stride = (XVar17 & 0xc) == 0;
                  goto LAB_00100604;
                }
                if (tmp_byte != 0xd) {
                  return FALSE;
                }
              }
              else {
                if (bVar16 >> 4 == 4) {
                  ctx_zero_stride = (0x1c57UL >> tmp_byte & 1) == 0;
                }
                else {
                  if (bVar16 >> 4 != 0) {
                    return FALSE;
                  }
                  ctx_zero_stride = (bVar16 & 0xb) == 3;
                }
LAB_00100604:
                if (ctx_zero_stride) {
                  return FALSE;
                }
              }
              ctx->opcode_offset = (char)pbVar14 - (char)code_start;
              if ((XVar12 == 0x3a00) && (2 < XVar11 - 0x4a)) goto LAB_0010063c;
            }
            ctx->imm_size = 0;
            goto LAB_001008c5;
          }
          uVar21 = XVar17 >> 3 & 0x1f;
          if (((byte)(&dasm_threebyte_0x38_is_valid)[uVar21] >> (XVar17 & 7) & 1) == 0) {
            return FALSE;
          }
          ctx->imm_size = 0;
          bVar16 = (&dasm_threebyte_has_modrm)[uVar21];
          ctx->opcode_offset = (u8)((long)pbVar14 - (long)code_start);
          if ((bVar16 >> (XVar17 & 7) & 1) != 0) goto LAB_001008c5;
          if (((ctx->prefix).decoded.flags2 & 8) == 0) {
            ctx->instruction = code_start;
            pbVar14 = (byte *)(((long)pbVar14 - (long)code_start) + 1);
            goto LAB_001004e1;
          }
LAB_0010067d:
          pbVar14 = pbVar14 + 1;
LAB_00100680:
          if (code_end <= pbVar14) goto LAB_00100aa5;
          derived_opcode = ctx->imm_size;
          bVar16 = *pbVar14;
          if (derived_opcode != 1) {
            cursor = pbVar14 + 1;
            if ((((ctx->prefix).decoded.flags & 4) != 0 && (ctx->prefix).decoded.osize_byte == 0x66)) {
            // AutoDoc: When an operand-size override is active (0x66 + DF2) flip 16- and 32-bit immediates so the decoded width stays accurate.
              if (derived_opcode == 2) {
                ctx->imm_size = 4;
              }
              else if (derived_opcode == 4) {
                ctx->imm_size = 2;
              }
            }
            if (code_end <= cursor) goto LAB_00100aa5;
            imm16_word = CONCAT11(*cursor,bVar16);
            if (ctx->imm_size == 2) {
              ctx->imm_zeroextended = (ulong)imm16_word;
              ctx->imm_signed = (long)(short)imm16_word;
              pbVar14 = cursor + (1 - (long)code_start);
              ctx->instruction = code_start;
              goto LAB_001007e4;
            }
            if (code_end <= pbVar14 + 2) goto LAB_00100aa5;
            pbVar20 = pbVar14 + 3;
            if (code_end <= pbVar20) goto LAB_00100aa5;
            uVar21 = CONCAT13(pbVar14[3],CONCAT12(pbVar14[2],imm16_word));
            if (ctx->imm_size == 4) {
              ctx->imm_zeroextended = (ulong)uVar21;
              derived_opcode = (u64)(int)uVar21;
            }
            else {
              if (((code_end <= pbVar14 + 4) || (code_end <= pbVar14 + 5)) ||
                 (code_end <= pbVar14 + 6)) goto LAB_00100aa5;
              pbVar20 = pbVar14 + 7;
              if (code_end <= pbVar20) goto LAB_00100aa5;
              derived_opcode = CONCAT17(pbVar14[7],
                               CONCAT16(pbVar14[6],CONCAT15(pbVar14[5],CONCAT14(pbVar14[4],uVar21)))
                              );
              ctx->imm_zeroextended = derived_opcode;
            }
            ctx->imm_signed = derived_opcode;
            goto LAB_0010089f;
          }
          ctx->imm_zeroextended = (ulong)bVar16;
          pbVar14 = pbVar14 + (1 - (long)code_start);
          ctx->imm_signed = (long)(char)bVar16;
          ctx->instruction = code_start;
          ctx->instruction_size = (u64)pbVar14;
        }
        else {
          if ((byte)(bVar16 + 0xe) < 2) goto LAB_001000cf;
LAB_00100191:
          if (code_end <= pbVar14) goto LAB_00100aa5;
          bVar16 = *pbVar14;
          opcode_class_offset = (ulong)bVar16;
          if (bVar16 == 0xf) {
            (ctx->opcode_window).opcode_window_dword = 0xf;
            cursor = pbVar14;
LAB_001001c5:
            pbVar14 = cursor + 1;
            goto LAB_001001c9;
          }
          XVar11 = (X86_OPCODE)bVar16;
          opcode_window_seed.opcode_window_dword._1_3_ = 0;
          opcode_window_seed.opcode_window[0] = bVar16;
          uVar21 = bVar16 & 7;
          if (((byte)(&dasm_onebyte_is_invalid)[bVar16 >> 3] >> uVar21 & 1) != 0) {
            return FALSE;
          }
          ctx->opcode_window = opcode_window_seed;
          opcode_class_masks[0] = 0x3030303030303030;
          ctx->opcode_offset = (u8)((long)pbVar14 - (long)code_start);
          opcode_class_masks[1] = 0xffff0fc000000000;
          opcode_class_masks[2] = 0xffff03000000000b;
          opcode_class_masks[3] = 0xc00bff000025c7;
          opcode_class_entry = opcode_class_masks[bVar16 >> 6] >> (bVar16 & 0x3f);
          opcode_class_mask = (ulong)((uint)opcode_class_entry & 1);
          if ((opcode_class_entry & 1) == 0) {
            ctx->imm_size = 0;
          }
          else {
            if (bVar16 < 0xf8) {
              if (bVar16 < 0xc2) {
                if (bVar16 < 0x6a) {
                  if (bVar16 < 0x2d) {
                    if (0x20 < (byte)(bVar16 - 5)) goto LAB_00100344;
                    opcode_class_entry = 0x2020202020;
                  }
                  else {
                    opcode_class_entry = 0x1800000000010101;
                    opcode_class_offset = (ulong)(bVar16 - 0x2d);
                  }
                }
                else {
                  opcode_class_entry = 0x7f80010000000001;
                  opcode_class_offset = (ulong)(bVar16 + 0x7f);
                  if (0x3e < (byte)(bVar16 + 0x7f)) goto LAB_00100344;
                }
                if ((opcode_class_entry >> (opcode_class_offset & 0x3f) & 1) != 0) {
                  opcode_class_mask = 4;
                }
              }
              else {
                opcode_class_offset = 1L << (bVar16 + 0x3e & 0x3f);
                if ((opcode_class_offset & 0x2000c800000020) == 0) {
                  if ((opcode_class_offset & 0x101) != 0) {
                    opcode_class_mask = 2;
                  }
                }
                else {
                  opcode_class_mask = 4;
                }
              }
            }
LAB_00100344:
            flags2_ptr = &(ctx->prefix).decoded.flags2;
            *flags2_ptr = *flags2_ptr | 8;
            ctx->imm_size = opcode_class_mask;
          }
          sVar10 = (sbyte)uVar21;
          cursor = pbVar14;
          if (((int)(uint)(byte)(&dasm_onebyte_has_modrm)[bVar16 >> 3] >> sVar10 & 1U) != 0)
          goto LAB_001008c5;
          if (3 < bVar16 - 0xa0) {
            tmp_byte = (ctx->prefix).decoded.flags2;
            if ((tmp_byte & 8) != 0) {
              if (((((ctx->prefix).decoded.flags & 0x20) != 0) &&
                  (((ctx->prefix).modrm_bytes.rex_byte & 8) != 0)) && ((bVar16 & 0xf8) == 0xb8)) {
                ctx->imm_size = 8;
                (ctx->prefix).decoded.flags2 = tmp_byte | 0x10;
                ctx->mov_imm_reg_index = sVar10;
                (ctx->opcode_window).opcode_window_dword = 0xb8;
              }
              goto LAB_0010067d;
            }
            ctx->instruction = code_start;
            pbVar14 = (byte *)(((long)pbVar14 - (long)code_start) + 1);
            goto LAB_001004e1;
          }
          flags2_ptr = &(ctx->prefix).decoded.flags2;
          *flags2_ptr = *flags2_ptr | 5;
LAB_0010065f:
          cursor = pbVar14 + 1;
LAB_0010073c:
          if (((code_end <= cursor) || (code_end <= cursor + 1)) || (code_end <= cursor + 2))
          goto LAB_00100aa5;
          pbVar20 = cursor + 3;
          if (code_end <= pbVar20) goto LAB_00100aa5;
          bVar16 = (ctx->prefix).decoded.flags2;
          ctx->mem_disp =
               (long)CONCAT13(cursor[3],CONCAT12(cursor[2],CONCAT11(cursor[1],*cursor)));
          if ((bVar16 & 4) == 0) {
            if ((bVar16 & 8) != 0) {
              pbVar14 = cursor + 4;
              goto LAB_00100680;
            }
LAB_0010089f:
            ctx->instruction = code_start;
            pbVar14 = pbVar20 + (1 - (long)code_start);
          }
          else {
            if (((code_end <= cursor + 4) || (code_end <= cursor + 5)) ||
               ((code_end <= cursor + 6 || (code_end <= cursor + 7)))) goto LAB_00100aa5;
            if ((bVar16 & 8) != 0) {
              pbVar14 = cursor + 8;
              goto LAB_00100680;
            }
            ctx->instruction = code_start;
            pbVar14 = cursor + 7 + (1 - (long)code_start);
          }
LAB_001007e4:
          ctx->instruction_size = (u64)pbVar14;
        }
        if (pbVar14 == (byte *)0x0) {
          return FALSE;
        }
        XVar11 = (ctx->opcode_window).opcode_window_dword;
LAB_001004ee:
        XVar11 = XVar11 + 0x80;
        goto LAB_001004f1;
      }
LAB_001000cf:
      bVar16 = (ctx->prefix).decoded.flags;
      if ((bVar16 & 1) != 0) {
        return FALSE;
      }
      (ctx->prefix).decoded.flags = bVar16 | 1;
      (ctx->prefix).decoded.lock_rep_byte = *pbVar14;
    }
LAB_00100675:
    pbVar14 = pbVar14 + 1;
    ctx_zero_stride = pbVar14 < code_end;
  } while( TRUE );
}

