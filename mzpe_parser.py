import argparse
import json
import struct

def get_str_from_address(file, addr):
    file.seek(addr)

    # Read the bytes into a bytearray until a null byte is encountered
    data = bytearray()
    while True:
        b = file.read(1)
        if b == b"\0":
            break
        data += b

    # Convert the bytearray to a string using ASCII encoding
    string = data.decode("ascii")

    return string

def get_str_addr_from_addr(file, addr):
    file.seek(addr)
    return struct.unpack("<L", file.read(4))[0]

def get_value_in_optional_context(file, optional_header_size, value):
    if file.tell() > optional_header_size:
        return None

    return value

def get_machine_name_from_hex(machine_hex):
    match machine_hex:
        case 0x184:
            return "Alpha AXP 32-bit"
        case 0x284:
            return "Alpha AXP 64-bit"
        case 0x1d3:
            return "Matsushita AM33"
        case 0x8664:
            return "AMD x64"
        case 0x1c0:
            return "ARM little endian"
        case 0xaa64:
            return "ARM64 little endian"
        case 0x1c4:
            return "ARM Thumb-2 little endian"
        case 0x284:
            return "AXP64"
        case 0xebc:
            return "EFI byte code"
        case 0x14c:
            return "Intel 386"
        case 0x200:
            return "Intel Itanium"
        case 0x6232:
            return "LoongArch 32-bit"
        case 0x6264:
            return "LoongArch 64-bit"
        case 0x9041:
            return "Mitsubishi M32R little endian"
        case 0x266:
            return "MIPS16"
        case 0x366:
            return "MIPS w FPU"
        case 0x466:
            return "MIPS16 w FPU"
        case 0x1f0:
            return "Power PC little endian"
        case 0x1f1:
            return "Power PC with floating point support"
        case 0x166:
            return "MIPS Little Endian"
        case 0x5032:
            return "RISC-V 32-bit"
        case 0x5064:
            return "RISC-V 64-bit"
        case 0x5128:
            return "RISC-V 128-bit"
        case 0x1a2:
            return "Hitachi SH3"
        case 0x1a3:
            return "Hitachi SH3 DSP"
        case 0x1a6:
            return "Hitachi SH4"
        case 0x1a8:
            return "Hitachi SH5"
        case 0x1c2:
            return "Thumb"
        case 0x169:
            return "MIPS little-endian WCE v2"


def parse_mzpe(file_path: str) -> dict:
    with open(file_path, 'rb') as f:
        # Read the DOS header (first 64 bytes)
        dos_header = f.read(64)
        e_lfanew = struct.unpack_from('<L', dos_header, 0x3c)[0]
        f.seek(e_lfanew)

        # Read the PE signature (4 bytes)
        pe_signature = f.read(4)

        if pe_signature != b'PE\x00\x00':
            raise ValueError('Invalid PE signature')

        machine = struct.unpack_from('H', f.read(2))[0]
        number_of_sections = struct.unpack_from('H', f.read(2))[0]
        timedate_stamp = struct.unpack_from('I', f.read(4))[0]
        pointer_to_symbol_table = struct.unpack_from('L', f.read(4))[0]
        number_of_symbols = struct.unpack_from('L', f.read(4))[0]
        size_of_optional_header = struct.unpack_from('H', f.read(2))[0]
        characteristics = struct.unpack_from('H', f.read(2))[0]

        coff_magic = struct.unpack_from('H', f.read(2))[0]

        if coff_magic == 0x20b:
            pe_format = 'PE32+'
        else:
            pe_format = 'PE32'

        major_linker_version = struct.unpack_from('B', f.read(1))[0]
        minor_linker_version = struct.unpack_from('B', f.read(1))[0]
        size_of_code = struct.unpack_from('L', f.read(4))[0]
        size_of_initialized_data = struct.unpack_from('L', f.read(4))[0]
        size_of_uninitialized_data = struct.unpack_from('L', f.read(4))[0]
        address_of_entry_point = struct.unpack_from('L', f.read(4))[0]
        base_of_code = struct.unpack_from('L', f.read(4))[0] if pe_format == 'PE32' else None
        base_of_data = struct.unpack_from('L', f.read(4))[0]

        # Windows-Specific Fields
        if pe_format == 'PE32':
            image_base = struct.unpack_from('L', f.read(4))[0]
        else:
            image_base = struct.unpack_from('Q', f.read(8))[0]

        section_alignment = struct.unpack_from('L', f.read(4))[0]
        file_alignment = struct.unpack_from('L', f.read(4))[0]
        major_operating_system_version = struct.unpack_from('H', f.read(2))[0]
        minor_operating_system_version = struct.unpack_from('H', f.read(2))[0]
        major_image_version = struct.unpack_from('H', f.read(2))[0]
        minor_image_version = struct.unpack_from('H', f.read(2))[0]
        major_subsystem_version = struct.unpack_from('H', f.read(2))[0]
        minor_subsystem_version = struct.unpack_from('H', f.read(2))[0]
        win32_version_value = struct.unpack_from('L', f.read(4))[0]
        size_of_image = struct.unpack_from('L', f.read(4))[0]
        size_of_headers = struct.unpack_from('L', f.read(4))[0]
        checksum = struct.unpack_from('L', f.read(4))[0]
        subsystem = struct.unpack_from('H', f.read(2))[0]
        dll_characteristics = struct.unpack_from('H', f.read(2))[0]

        if pe_format == 'PE32':
            size_of_stack_reserve = struct.unpack_from('L', f.read(4))[0]
            size_of_stack_commit = struct.unpack_from('L', f.read(4))[0]
            size_of_heap_reserve = struct.unpack_from('L', f.read(4))[0]
            size_of_heap_commit = struct.unpack_from('L', f.read(4))[0]
        else:
            size_of_stack_reserve = struct.unpack_from('Q', f.read(8))[0]
            size_of_stack_commit = struct.unpack_from('Q', f.read(8))[0]
            size_of_heap_reserve = struct.unpack_from('Q', f.read(8))[0]
            size_of_heap_commit = struct.unpack_from('Q', f.read(8))[0]

        loader_flags = struct.unpack_from('L', f.read(4))[0]
        number_of_rva_and_sizes = struct.unpack_from('L', f.read(4))[0]

        section_offset = e_lfanew + 24 + size_of_optional_header

        # read section headers
        f.seek(section_offset)
        sections = {}

        for i in range(number_of_sections):
            section_header = f.read(40)
            name = struct.unpack_from('8s', section_header, 0)[0]
            name = name.replace(b'\x00', b'').decode('utf-8')

            virtual_size = struct.unpack_from('L', section_header, 8)[0]
            virtual_address = struct.unpack_from('<L', section_header, 12)[0]
            size_of_raw_data = struct.unpack_from('<L', section_header, 16)[0]
            pointer_to_raw_data = struct.unpack_from('<L', section_header, 20)[0]
            pointer_to_relocations = struct.unpack_from('<L', section_header, 24)[0]
            pointer_to_linenumbers = struct.unpack_from('<L', section_header, 28)[0]
            number_of_relocations = struct.unpack_from('<H', section_header, 32)[0]
            number_of_linenumbers = struct.unpack_from('<H', section_header, 34)[0]
            characteristics = struct.unpack_from('<L', section_header, 36)[0]

            sections[name] = {
                'virtual_size': hex(virtual_size),
                'virtual_address': hex(virtual_address),
                'size_of_raw_data': hex(size_of_raw_data),
                'pointer_to_raw_data': hex(pointer_to_raw_data),
                'pointer_to_relocations': hex(pointer_to_relocations),
                'pointer_to_linenumbers': hex(pointer_to_linenumbers),
                'number_of_relocations': hex(number_of_relocations),
                'number_of_linenumbers': hex(number_of_linenumbers),
                'characteristics': hex(characteristics)
            }

        f.seek(int(sections.get(".idata").get("pointer_to_raw_data"), 16))
        import_directory = {}
        while True:
            import_instance = f.read(20)

            if import_instance == b'\x00' * 20:
                break

            import_lookup_table_rva = struct.unpack_from('<L', import_instance, 12)[0]
            time_date_stamp = struct.unpack_from('<L', import_instance, 4)[0]
            forwarder_chain = struct.unpack_from('<L', import_instance, 8)[0]
            name_rva = struct.unpack_from('<L', import_instance, 16)[0]
            first_thunk_rva = struct.unpack_from('<L', import_instance, 0)[0]

            import_directory[get_absolute_addr(name_rva, sections.get(".idata").get("virtual_address"), sections.get(".idata").get("pointer_to_raw_data"))] = {
                'import_lookup_table_rva': get_absolute_addr(import_lookup_table_rva, sections.get(".idata").get("virtual_address"), sections.get(".idata").get("pointer_to_raw_data")),
                'time_date_stamp': hex(time_date_stamp),
                'forwarder_chain': hex(forwarder_chain),
                'first_thunk_rva': get_absolute_addr(first_thunk_rva, sections.get(".idata").get("virtual_address"), sections.get(".idata").get("pointer_to_raw_data"))
            }

        for k,v in import_directory.items():
            # each key is an address to the address of the name of the used method ...
            method_name_addr = get_str_addr_from_addr(f, int(k, 16))
            method_name_addr = get_absolute_addr(method_name_addr, sections.get(".idata").get("virtual_address"), sections.get(".idata").get("pointer_to_raw_data"))
            import_directory[k]["method_name_addr"] = method_name_addr
            # add 2 to skip the null bytes of the previous strings
            import_directory[k]["method_name"] = get_str_from_address(f, int(method_name_addr, 16) + 2)
            import_directory[k]["dll_name"] = get_str_from_address(f, int(import_directory[k]["import_lookup_table_rva"], 16))

        readable_imports = {
            imp.get("method_name") : imp.get("dll_name") for imp in import_directory.values()
        }
        return {
            'machine': get_machine_name_from_hex(machine),
            'number_of_sections': hex(number_of_sections),
            'time_date_stamp': hex(timedate_stamp),
            'pointer_to_symbol_table': hex(pointer_to_symbol_table),
            'number_of_symbols': hex(number_of_symbols),
            'size_of_optional_header': hex(size_of_optional_header),
            'characteristics': hex(characteristics),
            'coff_magic': hex(coff_magic),
            'pe_format': pe_format,
            'major_linker_version': hex(major_linker_version),
            'minor_linker_version': hex(minor_linker_version),
            'size_of_code': hex(size_of_code),
            'size_of_initialized_data': hex(size_of_initialized_data),
            'size_of_uninitialized_data': hex(size_of_uninitialized_data),
            'address_of_entry_point': hex(address_of_entry_point),
            'base_of_code': hex(base_of_code),
            'base_of_data': hex(base_of_data),
            'windows_specific_fields': {
                'image_base': hex(image_base),
                'section_alignment': hex(section_alignment),
                'file_alignment': hex(file_alignment),
                'major_operating_system_version': hex(major_operating_system_version),
                'minor_operating_system_version': hex(minor_operating_system_version),
                'major_image_version': hex(major_image_version),
                'minor_image_version': hex(minor_image_version),
                'major_subsystem_version': hex(major_subsystem_version),
                'minor_subsystem_version': hex(minor_subsystem_version),
                'win32_version_value': hex(win32_version_value),
                'size_of_image': hex(size_of_image),
                'size_of_headers': hex(size_of_headers),
                'checksum': hex(checksum),
                'subsystem': hex(subsystem),
                'dll_characteristics': hex(dll_characteristics),
                'size_of_stack_reserve': hex(size_of_stack_reserve),
                'size_of_stack_commit': hex(size_of_stack_commit),
                'size_of_heap_reserve': hex(size_of_heap_reserve),
                'size_of_heap_commit': hex(size_of_heap_commit),
                'loader_flags': hex(loader_flags),
                'number_of_rva_and_sizes': hex(number_of_rva_and_sizes)
            },
            'sections': sections,
            'import_directory': import_directory,
            'readable_imports': readable_imports
        }


def get_absolute_addr(name_rva, virtual_address, raw_data_addr):
    return hex(name_rva - int(virtual_address, 16) + int(raw_data_addr, 16))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PE file parser')
    parser.add_argument('-f', '--file', help='PE file to parse', type=str)
    args = parser.parse_args()

    print(json.dumps(parse_mzpe(args.file), indent=4))