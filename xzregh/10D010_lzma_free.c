// /home/kali/xzre-ghidra/xzregh/10D010_lzma_free.c
// Function: lzma_free @ 0x10D010
// Calling convention: __stdcall
// Prototype: void __stdcall lzma_free(void * ptr, lzma_allocator * allocator)
/*
 * AutoDoc: Placeholder export for `lzma_free()` that funnels straight into `halt_baddata()`. The backdoor never expects this stub to run because it always routes work through the fake allocator, so entering it implies the GOT was not repointed and the process halts rather than corrupting memory.
 */

#include "xzre_types.h"


  halt_baddata();
}

