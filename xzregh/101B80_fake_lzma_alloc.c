// /home/kali/xzre-ghidra/xzregh/101B80_fake_lzma_alloc.c
// Function: fake_lzma_alloc @ 0x101B80
// Calling convention: __stdcall
// Prototype: void * __stdcall fake_lzma_alloc(void * opaque, size_t nmemb, size_t size)


void * fake_lzma_alloc(void *opaque,size_t nmemb,size_t size)

{
  EncodedStringId string_id;
  
  _string_id = elf_symbol_get_addr((elf_info_t *)opaque,(EncodedStringId)size);
  return _string_id;
}

