// /home/kali/xzre-ghidra/xzregh/102440_j_tls_get_addr.c
// Function: j_tls_get_addr @ 0x102440
// Calling convention: __stdcall
// Prototype: void * __stdcall j_tls_get_addr(tls_index * ti)


/*
 * AutoDoc: Generated from reverse engineering.
 *
 * Summary:
 *   Thin wrapper around the imported __tls_get_addr resolver so the loader can patch the GOT entry while still reaching the original implementation.
 */

void * j_tls_get_addr(tls_index *ti)

{
  void *pvVar1;
  
  pvVar1 = __tls_get_addr(ti);
  return pvVar1;
}

