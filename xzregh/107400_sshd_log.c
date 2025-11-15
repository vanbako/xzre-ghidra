// /home/kali/xzre-ghidra/xzregh/107400_sshd_log.c
// Function: sshd_log @ 0x107400
// Calling convention: __stdcall
// Prototype: void __stdcall sshd_log(sshd_log_ctx_t * log_ctx, LogLevel level, char * fmt, ...)


/*
 * AutoDoc: Wraps sshd's sshlogv() implementation by rebuilding a va_list on the stack, saving/restoring
 * XMM registers when necessary, and then tail-calling the resolved function pointer in the log
 * context. Every monitor hook routes formatted log lines through here so it matches OpenSSH's
 * logging ABI without needing libc wrappers.
 */

#include "xzre_types.h"

void sshd_log(sshd_log_ctx_t *log_ctx,LogLevel level,char *fmt,...)

{
  char in_AL;
  undefined8 in_RCX;
  undefined8 in_R8;
  undefined8 in_R9;
  undefined8 in_XMM0_Qa;
  undefined8 in_XMM1_Qa;
  undefined8 in_XMM2_Qa;
  undefined8 in_XMM3_Qa;
  undefined8 in_XMM4_Qa;
  undefined8 in_XMM5_Qa;
  undefined8 in_XMM6_Qa;
  undefined8 in_XMM7_Qa;
  u64 saved_xmm [16];
  undefined1 local_d1;
  undefined4 local_d0;
  undefined4 local_cc;
  va_list va_list_state;
  undefined1 *local_c0;
  undefined1 local_b8 [24];
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_78;
  undefined8 local_68;
  undefined8 local_58;
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_28;
  undefined8 local_18;
  
  if (in_AL != '\0') {
    local_88 = in_XMM0_Qa;
    local_78 = in_XMM1_Qa;
    local_68 = in_XMM2_Qa;
    local_58 = in_XMM3_Qa;
    local_48 = in_XMM4_Qa;
    local_38 = in_XMM5_Qa;
    local_28 = in_XMM6_Qa;
    local_18 = in_XMM7_Qa;
  }
  local_d1 = 0;
  va_list_state = &stack0x00000008;
  local_d0 = 0x18;
  local_c0 = local_b8;
  local_cc = 0x30;
  local_a0 = in_RCX;
  local_98 = in_R8;
  local_90 = in_R9;
  (*(code *)log_ctx->sshlogv)(&local_d1,&local_d1,0,0,level,0,fmt,&local_d0);
  return;
}

