// /home/kali/xzre-ghidra/xzregh/102C60_find_addr_referenced_in_mov_instruction.c
// Function: find_addr_referenced_in_mov_instruction @ 0x102C60
// Calling convention: __stdcall
// Prototype: void * __stdcall find_addr_referenced_in_mov_instruction(StringXrefId id, string_references_t * refs, void * mem_range_start, void * mem_range_end)
/*
 * AutoDoc: Scans a referenced function for MOV instructions that materialise an address inside the supplied data window. The backdoor uses it to recover struct-field pointers (for example the monitor sockets) so it can redirect them to its own handlers.
 */

#include "xzre_types.h"


