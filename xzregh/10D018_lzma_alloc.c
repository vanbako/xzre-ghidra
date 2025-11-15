// /home/kali/xzre-ghidra/xzregh/10D018_lzma_alloc.c
// Function: lzma_alloc @ 0x10D018
// Calling convention: __stdcall
// Prototype: void * __stdcall lzma_alloc(size_t size, lzma_allocator * allocator)


/*
 * AutoDoc: Counterpart to `lzma_free` that also traps. Once the loader installs the fake allocator the GOT entry is overwritten with `fake_lzma_alloc`; if execution ever reaches this stub it means the relocation failed and the safest option is to abort immediately.
 */

#include "xzre_types.h"

void * lzma_alloc(size_t size,lzma_allocator *allocator)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}

