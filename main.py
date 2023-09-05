from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, x86_const
from keystone import Ks, KS_ARCH_X86, KS_MODE_32

reg_map = {
    "EAX": x86_const.UC_X86_REG_EAX,
    "EBX": x86_const.UC_X86_REG_EBX,
    "ECX": x86_const.UC_X86_REG_ECX,
    "EDX": x86_const.UC_X86_REG_EDX,
    "ESI": x86_const.UC_X86_REG_ESI,
    "EDI": x86_const.UC_X86_REG_EDI,
    "EBP": x86_const.UC_X86_REG_EBP,
    "ESP": x86_const.UC_X86_REG_ESP
}


def print_context(uc: Uc):
    # TODO: EFLAGS

    for name in reg_map:
        print(f"{name}:  {hex(uc.reg_read(reg_map[name]))}")


uc = Uc(UC_ARCH_X86, UC_MODE_32)
ks = Ks(KS_ARCH_X86, KS_MODE_32)

ADDR = 0x1000000
PAGE_SIZE = uc.ctl_get_page_size()

code_txt = """
mov eax, 1
add eax, 2
"""

code, _ = ks.asm(code_txt, ADDR, True)
code_size = len(code)

uc.mem_map(ADDR, code_size + (PAGE_SIZE - code_size % PAGE_SIZE))
uc.mem_write(ADDR, code)

uc.emu_start(ADDR, ADDR + code_size)

print_context(uc)
