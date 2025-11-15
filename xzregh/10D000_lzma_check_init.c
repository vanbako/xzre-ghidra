// /home/kali/xzre-ghidra/xzregh/10D000_lzma_check_init.c
// Function: lzma_check_init @ 0x10D000
// Calling convention: __stdcall
// Prototype: void __stdcall lzma_check_init(lzma_check_state * state, lzma_check check_id)


/*
 * AutoDoc: Intentional trap stub for liblzma's `lzma_check_init()`. Until the loader patches this export to the real liblzma routine it
 * simply calls `halt_baddata()`, guaranteeing that any accidental execution stops immediately and signalling that someone tried to
 * run the object outside the curated runtime.
 */

#include "xzre_types.h"

void lzma_check_init(lzma_check_state *state,lzma_check check_id)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}

