// /home/kali/xzre-ghidra/xzregh/100020_x86_dasm.c
// Function: x86_dasm @ 0x100020
// Calling convention: __stdcall
// Prototype: BOOL __stdcall x86_dasm(dasm_ctx_t * ctx, u8 * code_start, u8 * code_end)


/*
 * AutoDoc: Logs a secret-data breadcrumb, zeros the supplied `dasm_ctx_t`, and decodes sequentially from `code_start`, handling legacy lock/REP prefixes, REX, and the two- and three-byte VEX encodings alongside ModRM/SIB and displacement/immediate operands. Prefix bookkeeping populates `ctx->opcode_window`, `opcode_offset`, `mem_disp`, and the signed/zero-extended immediates so MOV/LEA scanners can interrogate the context without re-running the decoder. Any invalid opcode, truncated buffer, or inconsistent prefix clears the context and returns FALSE so callers can advance one byte and retry; clean decodes leave `ctx->instruction`/`instruction_size` describing the instruction that was just observed.
 */

#include "xzre_types.h"

BOOL x86_dasm(dasm_ctx_t *ctx,u8 *code_start,u8 *code_end)

{
  u8 *puVar1;
  byte bVar2;
  byte modrm_byte;
  ushort uVar4;
  byte bVar5;
  BOOL BVar6;
  int iVar7;
  u64 uVar8;
  sbyte sVar9;
  uint uVar10;
  uint opcode;
  long lVar12;
  byte *pbVar13;
  u8 *cursor;
  byte bVar15;
  uint uVar16;
  uint normalized_opcode;
  ulong opcode_class_entry;
  byte *pbVar19;
  dasm_ctx_t *pdVar20;
  ulong uVar21;
  x86_prefix_state_t *pxVar22;
  BOOL bVar23;
  BOOL predicate_ok;
  BOOL range_hits_upper_bound;
  ulong opcode_class_masks [4];
  
  range_hits_upper_bound = 0;
  BVar6 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x12,0x46,2);
  // AutoDoc: Emit the breadcrumb before touching attacker-controlled bytes so later passes know a decode ran.
  if (BVar6 == FALSE) {
    return FALSE;
  }
  pdVar20 = ctx;
  // AutoDoc: Clear every field in the decoder context so prefixes/immediates never leak between attempts.
  for (lVar12 = 0x16; lVar12 != 0; lVar12 = lVar12 + -1) {
    *(undefined4 *)&pdVar20->instruction = 0;
    pdVar20 = (dasm_ctx_t *)((long)pdVar20 + (ulong)range_hits_upper_bound * -8 + 4);
  }
  bVar23 = code_start < code_end;
  pbVar13 = code_start;
  do {
  // AutoDoc: Decode sequentially until the cursor falls off the buffer or we fail a predicate.
    if (!bVar23) {
LAB_00100aa5:
      for (lVar12 = 0x16; lVar12 != 0; lVar12 = lVar12 + -1) {
        *(u32 *)&ctx->instruction = 0;
        ctx = (dasm_ctx_t *)((long)ctx + (ulong)range_hits_upper_bound * -8 + 4);
      }
      return FALSE;
    }
    bVar15 = *pbVar13;
    if (bVar15 < 0x68) {
      if (bVar15 < 0x2e) {
        if (bVar15 == 0xf) {
        // AutoDoc: 0x0F prefixes switch into the two-byte opcode table (with optional 0x38/0x3A extensions).
          *(u32 *)(ctx->opcode_window + 3) = 0xf;
          pbVar13 = pbVar13 + 1;
LAB_001001c9:
          if (code_end <= pbVar13) goto LAB_00100aa5;
          uVar10 = *(int *)(ctx->opcode_window + 3) << 8;
          *(uint *)(ctx->opcode_window + 3) = uVar10;
          bVar15 = *pbVar13;
          uVar10 = bVar15 | uVar10;
          *(uint *)(ctx->opcode_window + 3) = uVar10;
          bVar5 = *pbVar13;
          if ((bVar5 & 0xfd) == 0x38) {
            if (((ctx->prefix).decoded.flags & 0x10) != 0) {
              return FALSE;
            }
            pbVar13 = pbVar13 + 1;
            goto LAB_001003fa;
          }
          if (((int)(uint)(byte)(&dasm_twobyte_is_valid)[bVar5 >> 3] >> (bVar5 & 7) & 1U) == 0) {
            return FALSE;
          }
          if (((ctx->prefix).decoded.lock_rep_byte == 0xf3) && (bVar5 == 0x1e)) {
          // AutoDoc: Recognise ENDBR{32,64} quickly so the prologue walkers can bail early.
            if (pbVar13 + 1 < code_end) {
              pxVar22 = &ctx->prefix;
              for (lVar12 = 0x12; lVar12 != 0; lVar12 = lVar12 + -1) {
                pxVar22->flags_u32 = 0;
                pxVar22 = (x86_prefix_state_t *)((long)pxVar22 + (ulong)range_hits_upper_bound * -8 + 4);
              }
              ctx->instruction = code_start;
              ctx->instruction_size = 4;
              iVar7 = (pbVar13[1] == 0xfa) + 0xa5fc + (uint)(pbVar13[1] == 0xfa);
LAB_001004f1:
              *(int *)(ctx->opcode_window + 3) = iVar7;
              return TRUE;
            }
            goto LAB_00100aa5;
          }
          ctx->opcode_offset = (u8)((long)pbVar13 - (long)code_start);
          uVar16 = uVar10;
          if (((ctx->prefix).decoded.flags & 0x10) != 0) {
            uVar16 = (uint)bVar15;
          }
          if ((uVar16 & 0xf0) == 0x80) {
            uVar8 = 4;
LAB_001004a7:
            puVar1 = &(ctx->prefix).decoded.flags2;
            *puVar1 = *puVar1 | 8;
            ctx->imm_size = uVar8;
          }
          else {
            if ((byte)uVar16 < 0x74) {
              if (0x6f < (uVar16 & 0xff)) {
LAB_001004a2:
                uVar8 = 1;
                goto LAB_001004a7;
              }
            }
            else {
              opcode = (uVar16 & 0xff) - 0xa4;
              if ((opcode < 0x23) && ((0x740400101U >> ((byte)opcode & 0x3f) & 1) != 0))
              goto LAB_001004a2;
            }
            ctx->imm_size = 0;
          }
          cursor = pbVar13;
          if (((byte)(&dasm_twobyte_has_modrm)[uVar16 >> 3 & 0x1f] >> (uVar16 & 7) & 1) == 0) {
            if (((ctx->prefix).decoded.flags2 & 8) != 0) goto LAB_0010067d;
            ctx->instruction = code_start;
            pbVar13 = (byte *)(((long)pbVar13 - (long)code_start) + 1);
          }
          else {
LAB_001008c5:
            pbVar13 = cursor + 1;
            if (code_end <= pbVar13) goto LAB_00100aa5;
            bVar15 = (ctx->prefix).decoded.flags;
            (ctx->prefix).decoded.flags = bVar15 | 0x40;
            bVar5 = *pbVar13;
            (ctx->prefix).modrm_bytes.modrm_byte = bVar5;
            bVar5 = bVar5 >> 6;
            (ctx->prefix).modrm_bytes.modrm_mod = bVar5;
            bVar2 = *pbVar13;
            (ctx->prefix).modrm_bytes.modrm_reg = (byte)((int)(uint)bVar2 >> 3) & 7;
            modrm_byte = *pbVar13;
            (ctx->prefix).modrm_bytes.modrm_rm = modrm_byte & 7;
            if (bVar5 == 3) {
LAB_00100902:
              if (((ctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000) {
LAB_0010092e:
                puVar1 = &(ctx->prefix).decoded.flags2;
                *puVar1 = *puVar1 | 1;
              }
            }
            else {
              if ((modrm_byte & 7) == 4) {
                (ctx->prefix).decoded.flags = bVar15 | 0xc0;
              }
              if (bVar5 != 1) {
                if (bVar5 != 2) goto LAB_00100902;
                goto LAB_0010092e;
              }
              puVar1 = &(ctx->prefix).decoded.flags2;
              *puVar1 = *puVar1 | 3;
            }
            uVar10 = *(uint *)(ctx->opcode_window + 3);
            if ((uVar10 - 0xf6 < 2) && (((int)(uint)bVar2 >> 3 & 7U) != 0)) {
              puVar1 = &(ctx->prefix).decoded.flags2;
              *puVar1 = *puVar1 & 0xf7;
              ctx->imm_size = 0;
            }
            if ((char)(ctx->prefix).decoded.flags < '\0') {
              if (code_end <= cursor + 2) goto LAB_00100aa5;
              bVar15 = cursor[2];
              ctx->sib_byte = bVar15;
              ctx->sib_scale_bits = bVar15 >> 6;
              ctx->sib_index_bits = (byte)((int)(uint)cursor[2] >> 3) & 7;
              bVar15 = cursor[2];
              ctx->sib_base_bits = bVar15 & 7;
              if ((bVar15 & 7) == 5) {
                bVar15 = (ctx->prefix).modrm_bytes.modrm_mod;
                if ((bVar15 & 0xfd) == 0) {
                  puVar1 = &(ctx->prefix).decoded.flags2;
                  *puVar1 = *puVar1 | 1;
                }
                else if (bVar15 == 1) {
                  puVar1 = &(ctx->prefix).decoded.flags2;
                  *puVar1 = *puVar1 | 3;
                }
              }
              bVar15 = (ctx->prefix).decoded.flags2;
              if ((bVar15 & 2) == 0) {
                if ((bVar15 & 1) != 0) {
                  cursor = cursor + 3;
                  goto LAB_0010073c;
                }
                if ((bVar15 & 8) != 0) {
                  pbVar13 = cursor + 3;
                  goto LAB_00100680;
                }
                ctx->instruction = code_start;
                pbVar13 = cursor + 2 + (1 - (long)code_start);
                goto LAB_001004e1;
              }
              pbVar13 = cursor + 3;
LAB_001009ea:
              if (code_end <= pbVar13) goto LAB_00100aa5;
              bVar15 = (ctx->prefix).decoded.flags2;
              ctx->mem_disp = (long)(char)*pbVar13;
            }
            else {
              bVar15 = (ctx->prefix).decoded.flags2;
              if ((bVar15 & 2) != 0) {
                pbVar13 = cursor + 2;
                goto LAB_001009ea;
              }
              if ((bVar15 & 1) != 0) goto LAB_0010065f;
            }
            if ((bVar15 & 8) != 0) goto LAB_0010067d;
            ctx->instruction = code_start;
            pbVar13 = pbVar13 + (1 - (long)code_start);
          }
LAB_001004e1:
          ctx->instruction_size = (u64)pbVar13;
          if (pbVar13 == (byte *)0x0) {
            return FALSE;
          }
          goto LAB_001004ee;
        }
        if (bVar15 != 0x26) goto LAB_00100191;
      }
      else if ((0xc0000000010101U >> ((ulong)(bVar15 - 0x2e) & 0x3f) & 1) == 0) {
        if (bVar15 == 0x67) {
          bVar15 = (ctx->prefix).decoded.flags;
          if ((bVar15 & 8) != 0) {
            return FALSE;
          }
          (ctx->prefix).decoded.flags = bVar15 | 8;
          (ctx->prefix).decoded.asize_byte = *pbVar13;
        }
        else {
          if (bVar15 != 0x66) {
            if ((bVar15 & 0xf0) == 0x40) {
              (ctx->prefix).decoded.flags = (ctx->prefix).decoded.flags | 0x20;
              bVar15 = *pbVar13;
              pbVar13 = pbVar13 + 1;
              (ctx->prefix).modrm_bytes.rex_byte = bVar15;
            }
            goto LAB_00100191;
          }
          bVar15 = (ctx->prefix).decoded.flags;
          if (((bVar15 & 4) != 0) && ((ctx->prefix).decoded.osize_byte != 'f')) {
            return FALSE;
          }
          if ((bVar15 & 0x20) == 0) {
            (ctx->prefix).decoded.flags = (ctx->prefix).decoded.flags | 4;
            (ctx->prefix).decoded.osize_byte = *pbVar13;
          }
        }
        goto LAB_00100675;
      }
      bVar15 = (ctx->prefix).decoded.flags;
      if ((bVar15 & 2) != 0) {
        return FALSE;
      }
      (ctx->prefix).decoded.flags = bVar15 | 2;
      (ctx->prefix).decoded.seg_byte = *pbVar13;
    }
    else {
      if (bVar15 != 0xf0) {
        if (bVar15 < 0xf1) {
          if (1 < (byte)(bVar15 + 0x3c)) goto LAB_00100191;
          bVar5 = (ctx->prefix).decoded.flags;
          if ((bVar5 & 0x20) != 0) {
            return FALSE;
          }
          *(uint *)(ctx->opcode_window + 3) = (uint)bVar15;
          bVar2 = *pbVar13;
          cursor = pbVar13 + 1;
          (ctx->prefix).decoded.flags = bVar5 | 0x10;
          (ctx->prefix).decoded.vex_byte = bVar2;
          if (code_end <= cursor) goto LAB_00100aa5;
          bVar5 = pbVar13[1];
          (ctx->prefix).modrm_bytes.rex_byte = '@';
          uVar10 = (uint)bVar15 << 8 | 0xf;
          (ctx->prefix).decoded.vex_byte2 = bVar5;
          *(uint *)(ctx->opcode_window + 3) = uVar10;
          bVar15 = ((char)pbVar13[1] >> 7 & 0xfcU) + 0x44;
          (ctx->prefix).modrm_bytes.rex_byte = bVar15;
          if (bVar2 == 0xc5) goto LAB_001001c5;
          if (bVar2 != 0xc4) {
            return FALSE;
          }
          bVar2 = pbVar13[1];
          if ((bVar2 & 0x40) == 0) {
            (ctx->prefix).modrm_bytes.rex_byte = bVar15 | 2;
          }
          if ((pbVar13[1] & 0x20) == 0) {
            puVar1 = &(ctx->prefix).modrm_bytes.rex_byte;
            *puVar1 = *puVar1 | 1;
          }
          if (2 < (byte)((bVar2 & 0x1f) - 1)) {
            return FALSE;
          }
          if (code_end <= pbVar13 + 2) goto LAB_00100aa5;
          bVar15 = pbVar13[2];
          bVar5 = bVar5 & 0x1f;
          (ctx->prefix).decoded.vex_byte3 = bVar15;
          if (-1 < (char)bVar15) {
            puVar1 = &(ctx->prefix).modrm_bytes.rex_byte;
            *puVar1 = *puVar1 | 8;
          }
          uVar10 = uVar10 << 8;
          *(uint *)(ctx->opcode_window + 3) = uVar10;
          if (bVar5 == 2) {
            uVar10 = uVar10 | 0x38;
          }
          else {
            if (bVar5 != 3) {
              if (bVar5 != 1) {
                return FALSE;
              }
              pbVar13 = pbVar13 + 3;
              goto LAB_001001c9;
            }
            uVar10 = uVar10 | 0x3a;
          }
          *(uint *)(ctx->opcode_window + 3) = uVar10;
          pbVar13 = pbVar13 + 3;
LAB_001003fa:
          if (code_end <= pbVar13) goto LAB_00100aa5;
          opcode = *(int *)(ctx->opcode_window + 3) << 8;
          *(uint *)(ctx->opcode_window + 3) = opcode;
          bVar15 = *pbVar13;
          uVar10 = bVar15 | opcode;
          *(uint *)(ctx->opcode_window + 3) = uVar10;
          uVar16 = uVar10;
          if (((ctx->prefix).decoded.flags & 0x10) != 0) {
            uVar16 = (uint)bVar15 | opcode & 0xffffff;
          }
          opcode = uVar16 & 0xff00;
          cursor = pbVar13;
          if (opcode != 0x3800) {
            uVar10 = uVar16 & 0xff;
            bVar15 = (byte)uVar16;
            if (bVar15 < 0xf1) {
              if (uVar10 < 0xcc) {
                if (uVar10 < 0x3a) {
                  if (0x37 < uVar10) goto LAB_001005bf;
                  bVar23 = uVar10 - 0x20 < 2;
                  predicate_ok = uVar10 - 0x20 == 2;
                }
                else {
                  bVar23 = uVar10 - 0x60 < 3;
                  predicate_ok = uVar10 - 0x60 == 3;
                }
                if (!bVar23 && !predicate_ok) goto LAB_001005d6;
              }
              else if ((0x1000080001U >> (bVar15 + 0x34 & 0x3f) & 1) == 0) goto LAB_001005d6;
LAB_001005bf:
              ctx->opcode_offset = (char)pbVar13 - (char)code_start;
              if (opcode == 0x3a00) {
LAB_0010063c:
                puVar1 = &(ctx->prefix).decoded.flags2;
                *puVar1 = *puVar1 | 8;
                ctx->imm_size = 1;
                goto LAB_001008c5;
              }
            }
            else {
LAB_001005d6:
              bVar5 = bVar15 & 0xf;
              if (bVar15 >> 4 == 1) {
                if (bVar5 < 10) {
                  bVar23 = (uVar16 & 0xc) == 0;
                  goto LAB_00100604;
                }
                if (bVar5 != 0xd) {
                  return FALSE;
                }
              }
              else {
                if (bVar15 >> 4 == 4) {
                  bVar23 = (0x1c57UL >> bVar5 & 1) == 0;
                }
                else {
                  if (bVar15 >> 4 != 0) {
                    return FALSE;
                  }
                  bVar23 = (bVar15 & 0xb) == 3;
                }
LAB_00100604:
                if (bVar23) {
                  return FALSE;
                }
              }
              ctx->opcode_offset = (char)pbVar13 - (char)code_start;
              if ((opcode == 0x3a00) && (2 < uVar10 - 0x4a)) goto LAB_0010063c;
            }
            ctx->imm_size = 0;
            goto LAB_001008c5;
          }
          opcode = uVar16 >> 3 & 0x1f;
          if (((byte)(&dasm_threebyte_0x38_is_valid)[opcode] >> (uVar16 & 7) & 1) == 0) {
            return FALSE;
          }
          ctx->imm_size = 0;
          bVar15 = (&dasm_threebyte_has_modrm)[opcode];
          ctx->opcode_offset = (u8)((long)pbVar13 - (long)code_start);
          if ((bVar15 >> (uVar16 & 7) & 1) != 0) goto LAB_001008c5;
          if (((ctx->prefix).decoded.flags2 & 8) == 0) {
            ctx->instruction = code_start;
            pbVar13 = (byte *)(((long)pbVar13 - (long)code_start) + 1);
            goto LAB_001004e1;
          }
LAB_0010067d:
          pbVar13 = pbVar13 + 1;
LAB_00100680:
          if (code_end <= pbVar13) goto LAB_00100aa5;
          uVar8 = ctx->imm_size;
          bVar15 = *pbVar13;
          if (uVar8 != 1) {
            cursor = pbVar13 + 1;
            if ((((ctx->prefix).decoded.flags & 4) != 0 && (ctx->prefix).decoded.osize_byte == 0x66)) {
            // AutoDoc: When an operand-size override is active (0x66 + DF2) flip 16- and 32-bit immediates so the decoded width stays accurate.
              if (uVar8 == 2) {
                ctx->imm_size = 4;
              }
              else if (uVar8 == 4) {
                ctx->imm_size = 2;
              }
            }
            if (code_end <= cursor) goto LAB_00100aa5;
            uVar4 = CONCAT11(*cursor,bVar15);
            if (ctx->imm_size == 2) {
              ctx->imm_zeroextended = (ulong)uVar4;
              ctx->imm_signed = (long)(short)uVar4;
              pbVar13 = cursor + (1 - (long)code_start);
              ctx->instruction = code_start;
              goto LAB_001007e4;
            }
            if (code_end <= pbVar13 + 2) goto LAB_00100aa5;
            pbVar19 = pbVar13 + 3;
            if (code_end <= pbVar19) goto LAB_00100aa5;
            uVar10 = CONCAT13(pbVar13[3],CONCAT12(pbVar13[2],uVar4));
            if (ctx->imm_size == 4) {
              ctx->imm_zeroextended = (ulong)uVar10;
              uVar8 = (u64)(int)uVar10;
            }
            else {
              if (((code_end <= pbVar13 + 4) || (code_end <= pbVar13 + 5)) ||
                 (code_end <= pbVar13 + 6)) goto LAB_00100aa5;
              pbVar19 = pbVar13 + 7;
              if (code_end <= pbVar19) goto LAB_00100aa5;
              uVar8 = CONCAT17(pbVar13[7],
                               CONCAT16(pbVar13[6],CONCAT15(pbVar13[5],CONCAT14(pbVar13[4],uVar10)))
                              );
              ctx->imm_zeroextended = uVar8;
            }
            ctx->imm_signed = uVar8;
            goto LAB_0010089f;
          }
          ctx->imm_zeroextended = (ulong)bVar15;
          pbVar13 = pbVar13 + (1 - (long)code_start);
          ctx->imm_signed = (long)(char)bVar15;
          ctx->instruction = code_start;
          ctx->instruction_size = (u64)pbVar13;
        }
        else {
          if ((byte)(bVar15 + 0xe) < 2) goto LAB_001000cf;
LAB_00100191:
          if (code_end <= pbVar13) goto LAB_00100aa5;
          bVar15 = *pbVar13;
          uVar21 = (ulong)bVar15;
          if (bVar15 == 0xf) {
            *(u32 *)(ctx->opcode_window + 3) = 0xf;
            cursor = pbVar13;
LAB_001001c5:
            pbVar13 = cursor + 1;
            goto LAB_001001c9;
          }
          uVar10 = (uint)bVar15;
          uVar16 = bVar15 & 7;
          if (((byte)(&dasm_onebyte_is_invalid)[bVar15 >> 3] >> uVar16 & 1) != 0) {
            return FALSE;
          }
          *(uint *)(ctx->opcode_window + 3) = (uint)bVar15;
          opcode_class_masks[0] = 0x3030303030303030;
          ctx->opcode_offset = (u8)((long)pbVar13 - (long)code_start);
          opcode_class_masks[1] = 0xffff0fc000000000;
          opcode_class_masks[2] = 0xffff03000000000b;
          opcode_class_masks[3] = 0xc00bff000025c7;
          normalized_opcode = opcode_class_masks[bVar15 >> 6] >> (bVar15 & 0x3f);
          opcode_class_entry = (ulong)((uint)normalized_opcode & 1);
          if ((normalized_opcode & 1) == 0) {
            ctx->imm_size = 0;
          }
          else {
            if (bVar15 < 0xf8) {
              if (bVar15 < 0xc2) {
                if (bVar15 < 0x6a) {
                  if (bVar15 < 0x2d) {
                    if (0x20 < (byte)(bVar15 - 5)) goto LAB_00100344;
                    normalized_opcode = 0x2020202020;
                  }
                  else {
                    normalized_opcode = 0x1800000000010101;
                    uVar21 = (ulong)(bVar15 - 0x2d);
                  }
                }
                else {
                  normalized_opcode = 0x7f80010000000001;
                  uVar21 = (ulong)(bVar15 + 0x7f);
                  if (0x3e < (byte)(bVar15 + 0x7f)) goto LAB_00100344;
                }
                if ((normalized_opcode >> (uVar21 & 0x3f) & 1) != 0) {
                  opcode_class_entry = 4;
                }
              }
              else {
                uVar21 = 1L << (bVar15 + 0x3e & 0x3f);
                if ((uVar21 & 0x2000c800000020) == 0) {
                  if ((uVar21 & 0x101) != 0) {
                    opcode_class_entry = 2;
                  }
                }
                else {
                  opcode_class_entry = 4;
                }
              }
            }
LAB_00100344:
            puVar1 = &(ctx->prefix).decoded.flags2;
            *puVar1 = *puVar1 | 8;
            ctx->imm_size = opcode_class_entry;
          }
          sVar9 = (sbyte)uVar16;
          cursor = pbVar13;
          if (((int)(uint)(byte)(&dasm_onebyte_has_modrm)[bVar15 >> 3] >> sVar9 & 1U) != 0)
          goto LAB_001008c5;
          if (3 < bVar15 - 0xa0) {
            bVar5 = (ctx->prefix).decoded.flags2;
            if ((bVar5 & 8) != 0) {
              if (((((ctx->prefix).decoded.flags & 0x20) != 0) &&
                  (((ctx->prefix).modrm_bytes.rex_byte & 8) != 0)) && ((bVar15 & 0xf8) == 0xb8)) {
                ctx->imm_size = 8;
                (ctx->prefix).decoded.flags2 = bVar5 | 0x10;
                ctx->mov_imm_reg_index = sVar9;
                *(u32 *)(ctx->opcode_window + 3) = 0xb8;
              }
              goto LAB_0010067d;
            }
            ctx->instruction = code_start;
            pbVar13 = (byte *)(((long)pbVar13 - (long)code_start) + 1);
            goto LAB_001004e1;
          }
          puVar1 = &(ctx->prefix).decoded.flags2;
          *puVar1 = *puVar1 | 5;
LAB_0010065f:
          cursor = pbVar13 + 1;
LAB_0010073c:
          if (((code_end <= cursor) || (code_end <= cursor + 1)) || (code_end <= cursor + 2))
          goto LAB_00100aa5;
          pbVar19 = cursor + 3;
          if (code_end <= pbVar19) goto LAB_00100aa5;
          bVar15 = (ctx->prefix).decoded.flags2;
          ctx->mem_disp =
               (long)CONCAT13(cursor[3],CONCAT12(cursor[2],CONCAT11(cursor[1],*cursor)));
          if ((bVar15 & 4) == 0) {
            if ((bVar15 & 8) != 0) {
              pbVar13 = cursor + 4;
              goto LAB_00100680;
            }
LAB_0010089f:
            ctx->instruction = code_start;
            pbVar13 = pbVar19 + (1 - (long)code_start);
          }
          else {
            if (((code_end <= cursor + 4) || (code_end <= cursor + 5)) ||
               ((code_end <= cursor + 6 || (code_end <= cursor + 7)))) goto LAB_00100aa5;
            if ((bVar15 & 8) != 0) {
              pbVar13 = cursor + 8;
              goto LAB_00100680;
            }
            ctx->instruction = code_start;
            pbVar13 = cursor + 7 + (1 - (long)code_start);
          }
LAB_001007e4:
          ctx->instruction_size = (u64)pbVar13;
        }
        if (pbVar13 == (byte *)0x0) {
          return FALSE;
        }
        uVar10 = *(uint *)(ctx->opcode_window + 3);
LAB_001004ee:
        iVar7 = uVar10 + 0x80;
        goto LAB_001004f1;
      }
LAB_001000cf:
      bVar15 = (ctx->prefix).decoded.flags;
      if ((bVar15 & 1) != 0) {
        return FALSE;
      }
      (ctx->prefix).decoded.flags = bVar15 | 1;
      (ctx->prefix).decoded.lock_rep_byte = *pbVar13;
    }
LAB_00100675:
    pbVar13 = pbVar13 + 1;
    bVar23 = pbVar13 < code_end;
  } while( TRUE );
}

