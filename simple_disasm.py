"""
Simple x86 disassembler. Can only disassemble 32-bit x86 code. It's far from being something reliable.
It can disassemble code from an ELF file, but it's not reliable. It's just a proof of concept.
Also includes PE file parsing and disassembling, but it's not reliable at all.
"""

import re
import argparse
import struct


def index_error_results_false(func):
    """
    Decorator that avoids repeating a try-except for every function that tries to find the format, which would return
    False if an IndexError is raised (that would mean that the analyzed file had fewer bytes than expected for the
    format).
    """

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except IndexError:
            return False

    return wrapper


def has_content_after(file_chunk):
    if all(map(lambda x: x == "0x0", file_chunk)):
        return False

    return True

@index_error_results_false
def is_elf(file_chunk) -> bool:
    if not (hex(file_chunk[0]) == "0x7f" and hex(file_chunk[1]) == "0x45" and
            hex(file_chunk[2]) == "0x4c" and hex(file_chunk[3]) == "0x46"):
        return False

    if has_content_after(file_chunk[4:]):
        return True

    return False

def fix_string_with_spaces(string:str):
    if not string.replace(" ", "").isalnum():
        return string

    return string.replace(" ", "")

class OpcodeToASM:
    def __init__(self, corresponding_instruction: str, operand_num_of_bytes: int = 0, description: str = ""):
        self.corresponding_instruction = corresponding_instruction
        self.operand_num_of_bytes = operand_num_of_bytes
        self.description = description


def hex2ascii(byte):
    match byte:
        case "0xa":
            return "\\n"
        case "0x9":
            return "\\t"
        case "0x0":
            return "."
        case "0xd":
            return "\\r"
        case other:
            return chr(int(other, 0))


def get_opcode_to_asm_mapping(opcode):
    match opcode:
        case '0x4':
            return OpcodeToASM("add al, {}", 1, description="Add byte to AL")
        case '0x5':
            return OpcodeToASM("add eax, {}", 4, description="Add value to EAX")
        case '0x6':
            return OpcodeToASM("push es")
        case '0x7':
            return OpcodeToASM("pop es")
        case '0xc':
            return OpcodeToASM("or al, {}", 1)
        case '0xd':
            return OpcodeToASM("or eax, {}", 4)
        case '0xe':
            return OpcodeToASM("push cs")
        case '0x14':
            return OpcodeToASM("adc al, {}", 1)
        case '0x15':
            return OpcodeToASM("adc eax, {}", 4)
        case '0x16':
            return OpcodeToASM("push ss")
        case '0x17':
            return OpcodeToASM("pop ss")
        case '0x1c':
            return OpcodeToASM("sbb al, {}", 1)
        case '0x1d':
            return OpcodeToASM("sbb eax, {}", 4)
        case '0x1e':
            return OpcodeToASM("push ds")
        case '0x1f':
            return OpcodeToASM("pop ds")
        case '0x24':
            return OpcodeToASM("and al, {}", 1)
        case '0x25':
            return OpcodeToASM("and eax, {}", 4)
        case '0x26':
            return OpcodeToASM("es")
        case '0x27':
            return OpcodeToASM("daa")
        case '0x2c':
            return OpcodeToASM("sub al, {}", 1)
        case '0x2d':
            return OpcodeToASM("sub eax, {}", 4)
        case '0x2e':
            return OpcodeToASM("cs")
        case '0x2f':
            return OpcodeToASM("das")
        case '0x34':
            return OpcodeToASM("xor al, {}", 1)
        case '0x35':
            return OpcodeToASM("xor eax, {}", 4)
        case '0x36':
            return OpcodeToASM("ss")
        case '0x37':
            return OpcodeToASM("aaa", description='ASCII Adjust After Addition')
        case '0x3c':
            return OpcodeToASM("cmp al, {}", 1)
        case '0x3d':
            return OpcodeToASM("cmp eax, {}", 4)
        case '0x3e':
            return OpcodeToASM("ds")
        case '0x3f':
            return OpcodeToASM("aas")
        case '0x40':
            return OpcodeToASM("inc eax")
        case '0x41':
            return OpcodeToASM("inc ecx")
        case '0x42':
            return OpcodeToASM("inc edx")
        case '0x43':
            return OpcodeToASM("inc ebx")
        case '0x44':
            return OpcodeToASM("inc esp")
        case '0x45':
            return OpcodeToASM("inc ebp")
        case '0x46':
            return OpcodeToASM("inc esi")
        case '0x47':
            return OpcodeToASM("inc edi")
        case '0x48':
            return OpcodeToASM("dec eax")
        case '0x49':
            return OpcodeToASM("dec ecx")
        case '0x4a':
            return OpcodeToASM("dec edx")
        case '0x4b':
            return OpcodeToASM("dec ebx")
        case '0x4c':
            return OpcodeToASM("dec esp")
        case '0x4d':
            return OpcodeToASM("dec ebp")
        case '0x4e':
            return OpcodeToASM("dec esi")
        case '0x4f':
            return OpcodeToASM("dec edi")
        case '0x50':
            return OpcodeToASM("push eax")
        case '0x51':
            return OpcodeToASM("push ecx")
        case '0x52':
            return OpcodeToASM("push edx")
        case '0x53':
            return OpcodeToASM("push ebx")
        case '0x54':
            return OpcodeToASM("push esp")
        case '0x55':
            return OpcodeToASM("push ebp")
        case '0x56':
            return OpcodeToASM("push esi")
        case '0x57':
            return OpcodeToASM("push edi")
        case '0x58':
            return OpcodeToASM("pop eax")
        case '0x59':
            return OpcodeToASM("pop ecx")
        case '0x5A':
            return OpcodeToASM("pop edx")
        case '0x5B':
            return OpcodeToASM("pop ebx")
        case '0x5C':
            return OpcodeToASM("pop esp")
        case '0x5D':
            return OpcodeToASM("pop ebp")
        case '0x5E':
            return OpcodeToASM("pop esi")
        case '0x5F':
            return OpcodeToASM("pop edi")
        case '0x60':
            return OpcodeToASM("pusha", description="Push All General-Purpose Registers")
        case '0x61':
            return OpcodeToASM("popa", description="Pop All General-Purpose Registers")
        case '0x64':
            return OpcodeToASM("fs")
        case '0x65':
            return OpcodeToASM("gs")
        case '0x66':
            return OpcodeToASM("opsize", description="Operand-size override prefix")
        case '0x67':
            return OpcodeToASM("adsize", description="Address-size override prefix")
        case '0x68':
            return OpcodeToASM("push {}", 4)
        case '0x6a':
            return OpcodeToASM("push {}", 1)
        case '0x70':
            return OpcodeToASM("jo {}", 1, description="Jump short if overflow (OF=1)")
        case '0x71':
            return OpcodeToASM("jno {}", 1, description="Jump short if not overflow (OF=1)")
        case '0x72':
            return OpcodeToASM("jb {}", 1, description="Jump short if below/not above or equal/carry (CF=1)")
        case '0x73':
            return OpcodeToASM("jnb {}", 1, description="Jump short if not below/not above or equal/carry (CF=1)")
        case '0x74':
            return OpcodeToASM("jz {}", 1, description="Jump short if zero/equal (ZF=1)")
        case '0x75':
            return OpcodeToASM("jnz {}", 1, description="Jump short if not zero/equal (ZF=1)")
        case '0x76':
            return OpcodeToASM("jbe {}", 1, description="Jump short if below or equal/not above (CF=1 OR ZF=1)")
        case '0x77':
            return OpcodeToASM("ja {}", 1, description="Jump short if not below or equal/above (CF=0 AND ZF=0)")
        case '0x78':
            return OpcodeToASM("js {}", 1, description="Jump short if sign (SF=1)")
        case '0x79':
            return OpcodeToASM("jns {}", 1, description="Jump short if not sign (SF=0)")
        case '0x7a':
            return OpcodeToASM("jp {}", 1, description="Jump short if parity/parity even (PF=1)")
        case '0x7b':
            return OpcodeToASM("jnp {}", 1, description="Jump short if not parity/parity odd (PF=0)")
        case '0x7c':
            return OpcodeToASM("jl {}", 1, description="Jump short if less/not greater (SF!=OF)")
        case '0x7d':
            return OpcodeToASM("jnl {}", 1, description="Jump short if not less/greater or equal (SF=OF)")
        case '0x7e':
            return OpcodeToASM("jle {}", 1, description="Jump short if less or equal/not greater ((ZF=1) OR (SF!=OF))")
        case '0x7f':
            return OpcodeToASM("jnle {}", 1,
                               description="Jump short if not less nor equal/greater ((ZF=0) AND (SF=OF))")
        case '0x90':
            return OpcodeToASM("nop", description="No Operation")
        case '0x91':
            return OpcodeToASM("xchg eax, ecx")
        case '0x92':
            return OpcodeToASM("xchg eax, edx")
        case '0x93':
            return OpcodeToASM("xchg eax, ebx")
        case '0x94':
            return OpcodeToASM("xchg eax, esp")
        case '0x95':
            return OpcodeToASM("xchg eax, ebp")
        case '0x96':
            return OpcodeToASM("xchg eax, esi")
        case '0x97':
            return OpcodeToASM("xchg eax, edi")
        case '0x98':
            return OpcodeToASM("cbw", description="Convert Byte To Word")
        case '0x99':
            return OpcodeToASM("cwd", description="Convert Word To Double Word")
        case '0x9a':
            return OpcodeToASM("call {}", 4, description="call procedure")
        case '0x9b':
            return OpcodeToASM("wait")
        case '0x9e':
            return OpcodeToASM("sahf", description="Store AH into Flags")
        case '0x9f':
            return OpcodeToASM("lahf", description="Load Status Flags into AH Register")
        case '0xa0':
            return OpcodeToASM("mov al, {}", 1)
        case '0xa1':
            return OpcodeToASM("mov eax, {}", 4)
        # case '0xa2': return OpcodeToASM("")
        # case '0xa3': return OpcodeToASM("") - de rezolvat faza cu param inainte de const
        case '0xa8':
            return OpcodeToASM("test al, {}", 1)
        case '0xa9':
            return OpcodeToASM("test eax, {}", 4)
        case '0xb0':
            return OpcodeToASM("mov al, {}", 1)
        case '0xb1':
            return OpcodeToASM("mov cl, {}", 1)
        case '0xb2':
            return OpcodeToASM("mov dl, {}", 1)
        case '0xb3':
            return OpcodeToASM("mov bl, {}", 1)
        case '0xb4':
            return OpcodeToASM("mov ah, {}", 1, description="Move 1 byte value to AH")
        case '0xb5':
            return OpcodeToASM("mov ch, {}", 1, description="Move 1 byte value to CH")
        case '0xb6':
            return OpcodeToASM("mov dh, {}", 1, description="Move 1 byte value to DH")
        case '0xb7':
            return OpcodeToASM("mov bh, {}", 1, description="Move 1 byte value to BH")
        case '0xb8':
            return OpcodeToASM("mov eax, {}", 4, description="Move 4 byte value to EAX")
        case '0xb9':
            return OpcodeToASM("mov ecx, {}", 4, description="Move 4 byte value to ECX")
        case '0xba':
            return OpcodeToASM("mov edx, {}", 4, description="Move 4 byte value to EDX")
        case '0xbb':
            return OpcodeToASM("mov ebx, {}", 4, description="Move 4 byte value to EBX")
        case '0xbc':
            return OpcodeToASM("mov esp, {}", 4, description="Move 4 byte value to ESP")
        case '0xbd':
            return OpcodeToASM("mov ebp, {}", 4, description="Move 4 byte value to EBP")
        case '0xbe':
            return OpcodeToASM("mov esi, {}", 4, description="Move 4 byte value to ESI")
        case '0xbf':
            return OpcodeToASM("mov edi, {}", 4, description="Move 4 byte value to EDI")
        case '0xc2':
            return OpcodeToASM("retn {}", 2)
        case '0xc3':
            return OpcodeToASM("retn", description="Return; End of function")
        case '0xc9':
            return OpcodeToASM("leave")
        case '0xca':
            return OpcodeToASM("retf {}", 2)
        case '0xcb':
            return OpcodeToASM("retf")
        case '0xcc':
            return OpcodeToASM("int3")
        case '0xcd':
            return OpcodeToASM("int {}", 1, description="Call Interrupt with a given code")
        case '0xce':
            return OpcodeToASM("into", description="Call to Interrupt Procedure")
        case '0xcf':
            return OpcodeToASM("iret", description="Interrupt Return")
        case '0xd4':
            return OpcodeToASM("aam {}", 1, description="ASCII Adjust AX After Multiply")
        case '0xd5':
            return OpcodeToASM("aad {}", 1, description="ASCII Adjust AX Before Division")
        case '0xd6':
            return OpcodeToASM("salc", description="Set AL if Carry")
        case '0xd7':
            return OpcodeToASM("xlat", description="Table Look-up Translation")
        # d8 - df
        case '0xe0':
            return OpcodeToASM("loopnz {}", 1, description="Decrement count; Jump short if count!=0 and Z F=0")
        case '0xe1':
            return OpcodeToASM("loopz {}", 1, description="Decrement count; Jump short if count!=0 and ZF=1")
        case '0xe2':
            return OpcodeToASM("loop {}", 1, description="Decrement count; Jump short if count!=0")
        case '0xe3':
            return OpcodeToASM("jcxz {}", 1, description="Jump short if eCX register is 0")
        case '0xe4':
            return OpcodeToASM("in al, {}", 1, description="Input from Port")
        case '0xe5':
            return OpcodeToASM("in eax, {}", 1, description="Input from Port")
        case '0xe6':
            return OpcodeToASM("out {}, al", 1, description="Output to Port")
        case '0xe7':
            return OpcodeToASM("out {}, eax", 1, description="Output to Port")
        # e8-eb
        case '0xec':
            return OpcodeToASM("in al, dx", description="Input from Port")
        case '0xed':
            return OpcodeToASM("in eax, dx", description="Input from Port")
        case '0xee':
            return OpcodeToASM("out dx, al", description="Output to Port")
        case '0xef':
            return OpcodeToASM("out dx, eax", description="Output to Port")
        case '0xf0':
            return OpcodeToASM("lock", description="Assert LOCK# Signal Prefix")
        case '0xf2':
            return OpcodeToASM("repne", description="Repeat String Operation Prefix")
        case '0xf3':
            return OpcodeToASM("rep", description="Repeat String Operation Prefix")
        case '0xf4':
            return OpcodeToASM("hlt", description="Halt")
        case '0xf5':
            return OpcodeToASM("cmc", description="Complement Carry Flag")
        case '0xf8':
            return OpcodeToASM("clc", description="Clear Carry Flag")
        case '0xf9':
            return OpcodeToASM("stc", description="Set Carry Flag")
        case '0xfa':
            return OpcodeToASM("cli", description="Clear Interrupt Flag")
        case '0xfb':
            return OpcodeToASM("sti", description="Set Interrupt Flag")
        case '0xfc':
            return OpcodeToASM("cld", description="Clear Direction Flag")
        case '0xfd':
            return OpcodeToASM("std", description="Set Direction Flag")
        case other:
            return OpcodeToASM(f"unknown: {other}")

class DisassembledLine:
    def __init__(self, address: int, opcode: str, asm: str, ascii_vals: str, comment: str = None):
        self.address = address
        self.opcode = opcode
        self.asm = asm
        self.ascii = ascii_vals
        self.comment = comment
        self.printable = f"{hex(self.address).rjust(8, '0')}: {self.opcode.ljust(16)} ; {self.ascii.ljust(16)}; {self.asm.ljust(32)} ; {self.comment.ljust(32)}"

    def __repr__(self):
        return self.printable

    def __len__(self):
        return len(self.printable)


def get_register_values_for_syscall(syscalls):
    result = []
    for item in syscalls:
        eax, ebx, ecx, edx = None, None, None, None
        for instruction in item:
            if "eax" in instruction:
                eax = instruction.split(", ")[-1]
            elif "ebx" in instruction:
                ebx = instruction.split(", ")[-1]
            elif "ecx" in instruction:
                ecx = instruction.split(", ")[-1]
            elif "edx" in instruction:
                edx = instruction.split(", ")[-1]
        result.append({'eax': eax, 'ebx': ebx, 'ecx': ecx, 'edx': edx})
    return result


def infer_syscall(asm_instructions):
    syscalls = []
    for idx, line in enumerate(asm_instructions):
        if line.asm.startswith("int 0x80"):
            j = idx - 1
            syscall_instructions = []
            while asm_instructions[j].asm.startswith("mov"):
                syscall_instructions.append(asm_instructions[j].asm)
                j -= 1
            syscalls.append(syscall_instructions[::-1])

    translated_syscalls = []
    for reg_values in  get_register_values_for_syscall(syscalls):
        match reg_values.get('eax'):
            case '0x1':translated_syscalls.append(f'exit({reg_values.get("ebx")});')
            case '0x3':translated_syscalls.append(f'read({reg_values.get("ebx")}, (char*){reg_values.get("ecx")}, {reg_values.get("edx")});')
            case '0x4':
                ecx = reg_values.get("ecx")
                edx = reg_values.get("edx")

                addr = int(ecx, 16)
                length = int(edx, 16)

                referenced_str = ''.join([
                    fix_string_with_spaces(line.ascii) for line in asm_instructions
                    if addr <= line.address <= addr + length
                ])

                if referenced_str == '':
                    referenced_str = f"(const char*){ecx}"
                else:
                    referenced_str = f'"{referenced_str}"'

                translated_syscalls.append(f'write({reg_values.get("ebx")}, {referenced_str}, {reg_values.get("edx")});')
            case '0x5':translated_syscalls.append(f'open({reg_values.get("ebx")}, {reg_values.get("ecx")}, {reg_values.get("edx")});')
            case '0x6':translated_syscalls.append(f'close({reg_values.get("ebx")});')
            case '0x7':translated_syscalls.append(f'waitpid({reg_values.get("ebx")}, (unsigned int *){reg_values.get("ecx")}, {reg_values.get("edx")});')
            case '0x8':translated_syscalls.append(f'creat((const char *){reg_values.get("ebx")}, {reg_values.get("ecx")});')
            case '0x9':translated_syscalls.append(f'link((const char *){reg_values.get("ebx")}, (const char *){reg_values.get("ecx")});')
            case '0xa':translated_syscalls.append(f'unlink((const char *){reg_values.get("ebx")});')
            case '0xb':translated_syscalls.append(f'execve((struct pt_regs *){reg_values.get("ebx")});')
            case '0xc':translated_syscalls.append(f'chdir((const char *){reg_values.get("ebx")});')
            case '0xd':translated_syscalls.append(f'time((time_t *){reg_values.get("ebx")});')
            case '0xe':translated_syscalls.append(f'mknod((const char *){reg_values.get("ebx")}, {reg_values.get("ecx")}, (dev_t *){reg_values.get("edx")});')
            # .. https://faculty.nps.edu/cseagle/assembly/sys_call.html

    return translated_syscalls


class Disassembler:
    def __init__(self):
        self.base_address = None
        self.hexcode = None
        self.hex_text_re = re.compile(r'[A-Fa-f0-9 ]')

    def load_hex_from_elf(self, file_path: str):
        with open(file_path, "rb") as file:
            file_content = file.read()

        if not file_content:
            raise Exception("Given file is empty!")

        if not is_elf(file_content[:4096]):
            raise Exception("Given file is not an ELF file!")

        self.base_address = file_content[0x18]
        machine = file_content[0x12]

        if machine != 0x3:
            raise Exception("Given ELF file is not a 32-bit x86 ELF file!")

        self.hexcode = [hex(byte) for byte in file_content[self.base_address:]]


    def load_hex_from_mzpe(self, file_path:str):
        with open(file_path, 'rb') as f:
            # Read the DOS header (first 64 bytes)
            dos_header = f.read(64)
            e_lfanew = struct.unpack_from('<L', dos_header, 60)[0]
            f.seek(e_lfanew)

            # Read the PE signature (4 bytes)
            pe_signature = f.read(4)

            if pe_signature != b'PE\x00\x00':
                raise ValueError('Invalid PE signature')

            machine = struct.unpack_from('H', f.read(2))[0]

            if machine != 0x14c:
                raise ValueError(f'Invalid machine type: {hex(machine)}. Only x86 is supported.')

            number_of_sections = struct.unpack_from('H', f.read(2))[0]
            f.read(12) # skipping time_date_stamp, pointer_to_symbol_table, number_of_symbols
            size_of_optional_header = struct.unpack_from('H', f.read(2))[0]
            f.read(2) # skipping characteristics

            section_offset = e_lfanew + 24 + size_of_optional_header

            # read section headers
            f.seek(section_offset)

            text_header = None
            for i in range(number_of_sections):
                section_header = f.read(40)
                name = struct.unpack_from('8s', section_header, 0)[0]

                if name == b'.text\x00\x00\x00':
                    text_header = section_header
                    break

            # Check if the .text section was found
            if text_header is None:
                raise ValueError('.text section not found')

            size_of_raw_data = struct.unpack_from('<L', text_header, 16)[0]
            pointer_to_raw_data = struct.unpack_from('<L', text_header, 20)[0]

            f.seek(pointer_to_raw_data)
            self.hexcode = [hex(byte) for byte in f.read(size_of_raw_data)]

    def load_hex_from_file(self, file_path: str):
        hexcode = []
        with open(file_path, "rb") as file:
            while chunk := file.read(8192):
                hexcode.extend([hex(file_byte) for file_byte in chunk])

        self.hexcode = hexcode

    def load_hex_from_text(self, text: str):
        if not self.hex_text_re.match(text):
            raise Exception("Given text is invalid! It should only contain hex characters and spaces")

        text = text.replace(" ", "")

        if len(text) % 2 != 0:
            raise Exception("Given text is invalid! It should have an even number of characters (not counting spaces)!")

        self.hexcode = [hex(int(text[byte_idx:byte_idx + 2], 16)) for byte_idx in range(0, len(text), 2)]

    def get_dump(self, bytes_per_line: int = 8):
        if not self.hexcode:
            print("Cannot dump because hexcode wasn't loaded!")
            return

        dump_lines = []

        for hexcode_idx in range(0, len(self.hexcode), bytes_per_line):
            chunk = self.hexcode[hexcode_idx:hexcode_idx + bytes_per_line]
            ascii_equivalent = [chr(int(c, 0)) for c in chunk]
            beautiful_hex = [byte[2:].upper().zfill(2) for byte in chunk]
            beautiful_hex_string = ' '.join(beautiful_hex).ljust(bytes_per_line * 2 + bytes_per_line - 1)
            beatiful_ascii = ' '.join(ascii_equivalent).ljust(2 * bytes_per_line)

            dump_lines.append(f"{hex(hexcode_idx).rjust(8, ' ')} | {beautiful_hex_string} | {beatiful_ascii}")

        return dump_lines

    def print_dump(self):
        dump_lines = self.get_dump()
        max_line_length = len(max(dump_lines, key=len)) + 3

        print("DUMP")
        print("=" * max_line_length)

        for line in dump_lines:
            print(line)

        print("=" * max_line_length)
        print("END DUMP")

    def disassemble(self):
        done = False
        idx = 0
        hexcode_len = len(self.hexcode)
        asm_instructions = []

        while not done:
            byte = self.hexcode[idx]
            opcode_to_asm = get_opcode_to_asm_mapping(byte)
            initial_idx = idx
            idx += 1

            if (operand_n_of_bytes := opcode_to_asm.operand_num_of_bytes) != 0:
                if idx + operand_n_of_bytes < hexcode_len:
                    next_idx = idx + operand_n_of_bytes
                else:
                    next_idx = hexcode_len

                operand_bytes = [byte[2:].upper().zfill(2) for byte in self.hexcode[idx:next_idx]]
                little_endianed = f"0x{''.join([byte for byte in operand_bytes[::-1]]).lstrip('0')}"

                if len(little_endianed) == 2:
                    little_endianed += "0"

                final_instruction = opcode_to_asm.corresponding_instruction.format(little_endianed)

                idx = next_idx
            else:
                final_instruction = opcode_to_asm.corresponding_instruction

            if idx >= hexcode_len:
                done = True

            instr_opcodes = [byte[2:].upper().zfill(2) for byte in self.hexcode[initial_idx:idx]]
            ascii_equivalent = [hex2ascii(byte) for byte in self.hexcode[initial_idx:idx]]
            ascii_equivalent = ' '.join(ascii_equivalent)
            instr_opcodes = ' '.join(instr_opcodes)

            if self.base_address:
                address = self.base_address + initial_idx + 0x08048000
            else:
                address = initial_idx

            final_instruction = DisassembledLine(address, instr_opcodes, final_instruction, ascii_equivalent, opcode_to_asm.description)
            asm_instructions.append(final_instruction)

        addr = None
        for line in asm_instructions:
            if line.asm.startswith("mov ecx, 0x80"):
                addr = line.asm.split(", ")[1][2:]
                addr = int(addr, 16)
                break

        if addr:
            non_data_instr = [line for line in asm_instructions if line.address < addr]
            asm_instructions = non_data_instr + [
                DisassembledLine(line.address, line.opcode, "", line.ascii, "data")
                for line in asm_instructions if line.address >= addr
            ]

        syscalls = infer_syscall(asm_instructions)

        if syscalls:
            tmp_instr = []
            for idx, line in enumerate(asm_instructions):
                if line.asm.startswith("int 0x80"):
                    tmp_instr.append(DisassembledLine(line.address, line.opcode, line.asm,
                                                      line.ascii, f"Inferred C code: {syscalls.pop(0)}"))
                else:
                    tmp_instr.append(line)

            asm_instructions = tmp_instr

        return asm_instructions

    def print_assembly(self):
        dump_lines = self.disassemble()
        max_line_length = len(max(dump_lines, key=len)) + 3

        print("DISASSEMBLED INSTRUCTIONS")
        print("=" * max_line_length)

        for line in dump_lines:
            print(line)

        print("=" * max_line_length)
        print("END")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='Simple Python X86 Shellcode Disassembler',
        description='Disassembles x86_32 shellcode',
    )

    parser.add_argument('-t', '--text', type=str, required=False)
    parser.add_argument('-f', '--filepath', type=str, required=False)
    parser.add_argument('-e', '--elf-path', type=str, required=False)
    parser.add_argument('-p', '--pe-path', type=str, required=False)

    args = parser.parse_args()

    if not any([args.text, args.filepath, args.elf_path, args.pe_path]):
        raise Exception("Give at least a parameter.")

    if args.text and args.filepath:
        raise Exception("Cannot supply both text and filepath.")

    if args.text and args.elf_path:
        raise Exception("Cannot supply both text and elf path.")

    if args.text and args.pe_path:
        raise Exception("Cannot supply both text and PE path.")

    disasm = Disassembler()

    # plain shellcode
    if args.text:
        disasm.load_hex_from_text(args.text)
    elif args.filepath:
        disasm.load_hex_from_file(args.filepath)
    elif args.elf_path:
        disasm.load_hex_from_elf(args.elf_path)
    elif args.pe_path:
        disasm.load_hex_from_mzpe(args.pe_path)

    disasm.print_assembly()
    infer_syscall(disasm.disassemble())