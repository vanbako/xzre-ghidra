// /home/kali/xzre-ghidra/xzregh/101210_fake_lzma_free_noop.c
// Function: fake_lzma_free_noop @ 0x101210
// Calling convention: __stdcall
// Prototype: void __stdcall fake_lzma_free_noop(void * opaque, void * ptr)


/*
 * AutoDoc: No-op placeholder that exists solely to satisfy the liblzma allocator interface the implant exposes. The loader wires this stub into `lzma_allocator.free` until it can swap in the genuine host callbacks, so any invocation is guaranteed to do nothing other than prove that the fake allocator is still active.
 *
 * Having an inert body keeps the import surface small while still exporting a correctly typed symbol, and it gives the runtime a reliable indicator that a caller incorrectly tried to free memory through the bootstrap allocator.
 */

#include "xzre_types.h"

void fake_lzma_free_noop(void *opaque,void *ptr)

{
  // AutoDoc: Both `opaque` and `ptr` are ignored on purpose—the stub merely signals that the fake allocator table is still installed.
  return;
}

