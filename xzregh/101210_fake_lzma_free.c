// /home/kali/xzre-ghidra/xzregh/101210_fake_lzma_free.c
// Function: fake_lzma_free @ 0x101210
// Calling convention: __stdcall
// Prototype: void __stdcall fake_lzma_free(void * opaque, void * ptr)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief a fake free function called by lzma_free()
 *
 *   this function is a red herring as it is does nothing except make it look like lzma_alloc() is the real deal
 *
 *   @param opaque not used
 *   @param ptr not used
 *
 * Upstream implementation excerpt (xzre/xzre_code/fake_lzma_free.c):
 *     void fake_lzma_free(void *opaque, void *ptr){}
 */

void fake_lzma_free(void *opaque,void *ptr)

{
  return;
}

