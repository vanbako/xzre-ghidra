// /home/kali/xzre-ghidra/xzregh/101B80_fake_lzma_alloc.c
// Function: fake_lzma_alloc @ 0x101B80
// Calling convention: __stdcall
// Prototype: void * __stdcall fake_lzma_alloc(void * opaque, size_t nmemb, size_t size)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief a fake alloc function called by lzma_alloc() that then calls elf_symbol_get_addr()
 *
 *   @param opaque the parsed ELF context (elf_info_t*)
 *   @param nmemb not used
 *   @param size string ID of the symbol name (EncodedStringId)
 *   @return void* the address of the symbol
 *
 * Upstream implementation excerpt (xzre/xzre_code/fake_lzma_alloc.c):
 *     void *fake_lzma_alloc(void *opaque, size_t nmemb, size_t size){
 *     	elf_info_t *elf_info = (elf_info_t *)opaque;
 *     	EncodedStringId string_id = (EncodedStringId)size;
 *     	return elf_symbol_get_addr(elf_info, string_id);
 *     }
 */

void * fake_lzma_alloc(void *opaque,size_t nmemb,size_t size)

{
  EncodedStringId string_id;
  
  _string_id = elf_symbol_get_addr((elf_info_t *)opaque,(EncodedStringId)size);
  return _string_id;
}

