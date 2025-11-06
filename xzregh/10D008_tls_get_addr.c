// /home/kali/xzre-ghidra/xzregh/10D008_tls_get_addr.c
// Function: __tls_get_addr @ 0x10D008
// Calling convention: __stdcall
// Prototype: void * __stdcall __tls_get_addr(tls_index * ti)
/*
 * AutoDoc: Generated from reverse engineering.
 *
 * Summary:
 *   Placeholder for __tls_get_addr that merely raises halt_baddata(); the object relies on the dynamic loader to wire in the system resolver.
 *
 * Notes:
 *   - Keeps the GOT slot and relocation records intact while preventing accidental execution of an unimplemented body.
 */

/* WARNING: Control flow encountered bad instruction data */

void * __tls_get_addr(tls_index *ti)

{
                    /* WARNING: Bad instruction - Truncating control flow here */
  halt_baddata();
}

