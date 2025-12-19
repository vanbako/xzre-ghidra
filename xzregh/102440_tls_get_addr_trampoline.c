// /home/kali/xzre-ghidra/xzregh/102440_tls_get_addr_trampoline.c
// Function: tls_get_addr_trampoline @ 0x102440
// Calling convention: __stdcall
// Prototype: void * __stdcall tls_get_addr_trampoline(tls_index * ti)


/*
 * AutoDoc: Thin trampoline that jumps straight into glibc's `__tls_get_addr`. Stage two keeps both exports (the trapping stub and this wrapper) alive so relocations can point at the trap until the loader patches GOT entries to the legit resolver via `tls_get_addr_trampoline`.
 */

#include "xzre_types.h"

void * tls_get_addr_trampoline(tls_index *ti)

{
  void *resolved_tls;
  
  // AutoDoc: Always delegate to glibc—the wrapper only exists so the hook infrastructure has a trusted target.
  resolved_tls = __tls_get_addr(ti);
  return resolved_tls;
}

