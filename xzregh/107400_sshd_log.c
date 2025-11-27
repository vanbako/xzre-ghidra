// /home/kali/xzre-ghidra/xzregh/107400_sshd_log.c
// Function: sshd_log @ 0x107400
// Calling convention: __stdcall
// Prototype: void __stdcall sshd_log(sshd_log_ctx_t * log_ctx, LogLevel level, char * fmt, ...)


/*
 * AutoDoc: Mirrors sshd’s `sshlogv()` calling convention. It saves the incoming SSE argument registers when the ABI says variadic vector arguments are present, rebuilds a fresh `va_list` (gp/fp offsets plus overflow/stack areas), and finally tail-calls the resolved `sshlogv` pointer stored in the logging context so higher-level hooks can format log lines exactly the way sshd expects.
 */

#include "xzre_types.h"

void sshd_log(sshd_log_ctx_t *log_ctx,LogLevel level,char *fmt,...)

{
  char in_AL;
  u64 incoming_rcx;
  u64 incoming_r8;
  u64 incoming_r9;
  u64 incoming_xmm0;
  u64 incoming_xmm1;
  u64 incoming_xmm2;
  u64 incoming_xmm3;
  u64 incoming_xmm4;
  u64 incoming_xmm5;
  u64 incoming_xmm6;
  u64 incoming_xmm7;
  u64 saved_xmm [16];
  BOOL sse_args_present;
  u32 va_gp_offset;
  u32 va_fp_offset;
  va_list va_list_state;
  void *overflow_arg_area;
  u8 reg_save_area[24];
  u64 saved_rcx;
  u64 saved_r8;
  u64 saved_r9;
  u64 saved_xmm0;
  u64 saved_xmm1;
  u64 saved_xmm2;
  u64 saved_xmm3;
  u64 saved_xmm4;
  u64 saved_xmm5;
  u64 saved_xmm6;
  u64 saved_xmm7;
  
  // AutoDoc: When the caller flagged vector arguments, spill the incoming XMM registers so they can be replayed.
  if (in_AL != '\0') {
    saved_xmm0 = incoming_xmm0;
    saved_xmm1 = incoming_xmm1;
    saved_xmm2 = incoming_xmm2;
    saved_xmm3 = incoming_xmm3;
    saved_xmm4 = incoming_xmm4;
    saved_xmm5 = incoming_xmm5;
    saved_xmm6 = incoming_xmm6;
    saved_xmm7 = incoming_xmm7;
  }
  sse_args_present = 0;
  // AutoDoc: Recreate the gp/fp offsets, overflow area, and `va_list` pointer exactly the way sshlogv expects.
  va_list_state = &stack0x00000008;
  va_gp_offset = 0x18;
  overflow_arg_area = reg_save_area;
  va_fp_offset = 0x30;
  saved_rcx = incoming_rcx;
  saved_r8 = incoming_r8;
  saved_r9 = incoming_r9;
  // AutoDoc: Tail-call sshd’s real sshlogv() implementation so our wrapper stays transparent.
  (*(code *)log_ctx->sshlogv_impl)(&sse_args_present,&sse_args_present,0,0,level,0,fmt,&va_gp_offset);
  return;
}

