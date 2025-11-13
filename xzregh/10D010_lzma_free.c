// /home/kali/xzre-ghidra/xzregh/10D010_lzma_free.c
// Function: lzma_free @ 0x10D010
// Calling convention: unknown
// Prototype: undefined lzma_free(void)


/*
 * AutoDoc: Placeholder export for `lzma_free()` that funnels straight into `halt_baddata()`. The backdoor never expects this stub to run because it always routes work through the fake allocator, so entering it implies the GOT was not repointed and the process halts rather than corrupting memory.
 */
#include "xzre_types.h"


void lzma_free(void)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}

