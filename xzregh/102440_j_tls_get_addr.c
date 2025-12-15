// /home/kali/xzre-ghidra/xzregh/102440_j_tls_get_addr.c
// Function: j_tls_get_addr @ 0x102440
// Calling convention: __stdcall
// Prototype: void * __stdcall j_tls_get_addr(tls_index * ti)


/*
 * AutoDoc: Thin trampoline that jumps straight into glibc's `__tls_get_addr`. Stage two keeps both exports (the trapping stub and this wrapper) alive so relocations can point at the trap until the loader patches GOT entries to the legit resolver via `j_tls_get_addr`.
 */

#include "xzre_types.h"

void * j_tls_get_addr(tls_index *ti)

{
  void *resolved_tls;
  
  // AutoDoc: Always delegate to glibc—the wrapper only exists so the hook infrastructure has a trusted target.
  resolved_tls = __tls_get_addr(ti);
  return resolved_tls;
}

