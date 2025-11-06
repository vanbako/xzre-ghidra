// /home/kali/xzre-ghidra/xzregh/10D018_lzma_alloc.c
// Function: lzma_alloc @ 0x10D018
// Calling convention: __stdcall
// Prototype: void * __stdcall lzma_alloc(size_t size, lzma_allocator * allocator)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief lzma_alloc function, used by the backdoor as an ELF symbol resolver
 *   the @p allocator 's opaque field must point to a parsed @ref elf_info_t
 *
 *   @param size the encoded string ID of the function to resolve
 *   @param allocator the fake lzma allocator referring to the @ref elf_info_t to search into.
 *
 * Upstream implementation excerpt (xzre/xzre_code/lzma_alloc.c):
 *     void *fake_lzma_alloc(void *opaque, size_t nmemb, size_t size){
 *     	elf_info_t *elf_info = (elf_info_t *)opaque;
 *     	EncodedStringId string_id = (EncodedStringId)size;
 *     	return elf_symbol_get_addr(elf_info, string_id);
 *     }
 */

/* WARNING: Control flow encountered bad instruction data */

void * lzma_alloc(size_t size,lzma_allocator *allocator)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}

