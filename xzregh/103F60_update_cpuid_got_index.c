// /home/kali/xzre-ghidra/xzregh/103F60_update_cpuid_got_index.c
// Function: update_cpuid_got_index @ 0x103F60
// Calling convention: __stdcall
// Prototype: void __stdcall update_cpuid_got_index(elf_entry_ctx_t * ctx)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief get the cpuid() GOT index
 *
 *   stores the index in elf_entry_ctx_t::cpuid_fn
 *
 *   @param ctx
 *   @return u64 cpuid() GOT index
 *
 * Upstream implementation excerpt (xzre/xzre_code/update_cpuid_got_index.c):
 *     void update_cpuid_got_index(elf_entry_ctx_t *ctx){
 *     	ctx->got_ctx.cpuid_fn = (void *)cpuid_reloc_consts.cpuid_got_index;
 *     }
 */

void update_cpuid_got_index(elf_entry_ctx_t *ctx)

{
  (ctx->got_ctx).cpuid_fn = tls_get_addr_reloc_consts;
  return;
}

