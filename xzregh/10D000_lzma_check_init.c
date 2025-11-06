// /home/kali/xzre-ghidra/xzregh/10D000_lzma_check_init.c
// Function: lzma_check_init @ 0x10D000
// Calling convention: __stdcall
// Prototype: void __stdcall lzma_check_init(lzma_check_state * state, lzma_check check_id)


/*
 * AutoDoc: Generated from reverse engineering.
 *
 * Summary:
 *   Stub for liblzma's lzma_check_init() that intentionally traps via halt_baddata(); the real implementation lives in the host process and must be resolved through relocation.
 *
 * Notes:
 *   - Exists so the object exports a symbol with the right signature while still ensuring execution never reaches the incomplete clone.
 *   - The loader patches this slot with the genuine routine when linking against liblzma.
 */

/* WARNING: Control flow encountered bad instruction data */

void lzma_check_init(lzma_check_state *state,lzma_check check_id)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}

