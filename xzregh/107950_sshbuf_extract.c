// /home/kali/xzre-ghidra/xzregh/107950_sshbuf_extract.c
// Function: sshbuf_extract @ 0x107950
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshbuf_extract(sshbuf * buf, global_context_t * ctx, void * * p_sshbuf_d, size_t * p_sshbuf_size)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief checks if the provided @p buf is sane, then decomposes it into @p p_sshbuf_d and @p p_sshbuf_size
 *
 *   @param buf pointer to `struct sshbuf` to decompose
 *   @param ctx the global context
 *   @param p_sshbuf_d output variable that will receive the address of the sshbuf data
 *   @param p_sshbuf_size output variable that will receive the size of the sshbuf data
 *   @return BOOL TRUE if the sshbuf was decomposed successfully, FALSE otherwise
 */

BOOL sshbuf_extract(sshbuf *buf,global_context_t *ctx,void **p_sshbuf_d,size_t *p_sshbuf_size)

{
  byte bVar1;
  byte bVar2;
  BOOL BVar3;
  ulong uVar4;
  ulong uVar5;
  u64 uVar6;
  u8 *addr;
  
  if (ctx == (global_context_t *)0x0) {
    return 0;
  }
  if (((buf != (sshbuf *)0x0) && (p_sshbuf_d != (void **)0x0)) && (p_sshbuf_size != (size_t *)0x0))
  {
    bVar1 = *(byte *)((long)&(ctx->sshd_offsets).field0_0x0 + 3);
    bVar2 = *(byte *)((long)&(ctx->sshd_offsets).field0_0x0 + 2);
    if ((char)(bVar1 & bVar2) < '\0') {
      uVar4 = 0;
      uVar5 = 0;
      uVar6 = 0x48;
    }
    else {
      uVar4 = (ulong)((int)(char)bVar1 << 3);
      uVar5 = (ulong)((int)(char)bVar2 << 3);
      uVar6 = uVar4 + 8;
      if (uVar4 < uVar5) {
        uVar6 = uVar5 + 8;
      }
    }
    BVar3 = is_range_mapped((u8 *)buf,uVar6,ctx);
    if (BVar3 != 0) {
      if (*(char *)((long)&(ctx->sshd_offsets).field0_0x0 + 2) < '\0') {
        addr = buf->d;
      }
      else {
        addr = *(u8 **)((long)&buf->d + uVar5);
      }
      *p_sshbuf_d = addr;
      if (*(char *)((long)&(ctx->sshd_offsets).field0_0x0 + 3) < '\0') {
        uVar6 = buf->size;
      }
      else {
        uVar6 = *(u64 *)((long)&buf->d + uVar4);
      }
      *p_sshbuf_size = uVar6;
      BVar3 = is_range_mapped(addr,uVar6,ctx);
      return (uint)(BVar3 != 0);
    }
  }
  return 0;
}

