"""
Simple x86 disassembler. Succesfully used in reversing a shellcode found in a '.com' file. Probably useless for large coms and clearly useless for structured executables.
A dump for the file is also provided.
"""

import re
import argparse


class OpcodeToASM:
    def __init__(self, corresponding_instruction: str, operand_num_of_bytes: int = 0, description: str = ""):
        self.corresponding_instruction = corresponding_instruction
        self.operand_num_of_bytes = operand_num_of_bytes
        self.description = description


def hex2ascii(byte):
    match byte:
        case "0x0":
            return "\\0"
        case "0xa":
            return "\\n"
        case "0x9":
            return "\\t"
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
            return OpcodeToASM("test al, {]", 1)
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


class Disassembler:
    def __init__(self):
        self.hexcode = None
        self.hex_text_re = re.compile(r'[A-Fa-f0-9 ]')

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

            dump_lines.append(f"{beautiful_hex_string} | {beatiful_ascii}")

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
                little_endianed = ''.join([byte for byte in operand_bytes[::-1]])
                final_instruction = opcode_to_asm.corresponding_instruction.format(little_endianed)

                idx = next_idx

                if len(little_endianed) != operand_n_of_bytes * 2:
                    final_instruction = f"{final_instruction} [INCOMPLETE]"
            else:
                final_instruction = opcode_to_asm.corresponding_instruction

            if idx >= hexcode_len:
                done = True

            instr_opcodes = [byte[2:].upper().zfill(2) for byte in self.hexcode[initial_idx:idx]]
            ascii_equivalent = [hex2ascii(byte) for byte in self.hexcode[initial_idx:idx]]
            ascii_equivalent = ' '.join(ascii_equivalent)
            instr_opcodes = ' '.join(instr_opcodes)
            final_instruction = f"{instr_opcodes.ljust(16)} ; {ascii_equivalent.ljust(16)} ; {final_instruction.ljust(32)} ; {opcode_to_asm.description}"
            asm_instructions.append(final_instruction)

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

    args = parser.parse_args()

    if not any([args.text, args.filepath]):
        raise Exception("Give at least a parameter.")

    if args.text and args.filepath:
        raise Exception("Cannot supply both text and filepath.")

    disasm = Disassembler()

    if args.text:
        disasm.load_hex_from_text(args.text)
    elif args.filepath:
        disasm.load_hex_from_file(args.filepath)

    disasm.print_assembly()