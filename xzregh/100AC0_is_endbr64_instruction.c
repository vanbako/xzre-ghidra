// /home/kali/xzre-ghidra/xzregh/100AC0_is_endbr64_instruction.c
// Function: is_endbr64_instruction @ 0x100AC0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall is_endbr64_instruction(u8 * code_start, u8 * code_end, u32 low_mask_part)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief Checks if the code between @p code_start and @p code_end is an endbr64 instruction.
 *
 *
 *   the checks is encoded as following (note: An endbr64 instruction is encoded as <code>F3 0F 1E FA</code>)
 *   @code
 *   // as 32bit quantities, so 0x10000f223 -> f223
 *   (0xFA1E0FF3 + (0xE230 | 0x5E20000)) == 0xF223
 *   @endcode
 *   and 0xE230 is always passed as an argument to prevent compiler optimizations and for further obfuscation.
 *
 *   @param code_start pointer to the first byte of the instruction to test
 *   @param code_end pointer to the last byte of the instruction to test
 *   @param low_mask_part the constant 0xE230
 *   @return BOOL TRUE if the instruction is an endbr64, FALSE otherwise
 *
 * Upstream implementation excerpt (xzre/xzre_code/is_endbr64_instruction.c):
 *     BOOL is_endbr64_instruction(u8 *code_start, u8 *code_end, u32 low_mask_part){
 *     	if((code_end - code_start) > 3){
 *     		return *code_start + (low_mask_part | 0x5E20000) == 0xF223;
 *     	}
 *     	return FALSE;
 *     }
 */

BOOL is_endbr64_instruction(u8 *code_start,u8 *code_end,u32 low_mask_part)

{
  uint uVar1;
  
  uVar1 = 0;
  if (3 < (long)code_end - (long)code_start) {
    uVar1 = (uint)((low_mask_part | 0x5e20000) + *(int *)code_start == 0xf223);
  }
  return uVar1;
}

