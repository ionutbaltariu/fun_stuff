import struct

def parse_elf(file_path: str) -> dict:
    with open(file_path, 'rb') as f:
        magic = f.read(4)

        if magic != b'\x7fELF':
            print("Not an ELF file!")
            return {}

        ei_class = struct.unpack_from('B', f.read(1))[0]
        ei_data = struct.unpack_from('B', f.read(1))[0]
        ei_version = struct.unpack_from('B', f.read(1))[0]
        size = '32' if ei_class == 1 else '64'
        ei_osabi = struct.unpack_from('B', f.read(1))[0]
        ei_abiversion = struct.unpack_from('B', f.read(1))[0]
        f.read(7) # skip padding
        e_type = struct.unpack_from('H', f.read(2))[0]
        e_machine = struct.unpack_from('H', f.read(2))[0]
        e_version = struct.unpack_from('I', f.read(4))[0]
        e_entry = struct.unpack_from('I' if size == '32' else 'Q', f.read(4 if size == '32' else 8))[0]
        e_phoff = struct.unpack_from('I' if size == '32' else 'Q', f.read(4 if size == '32' else 8))[0]
        e_shoff = struct.unpack_from('I' if size == '32' else 'Q', f.read(4 if size == '32' else 8))[0]
        e_flags = struct.unpack_from('I', f.read(4))[0]
        e_ehsize = struct.unpack_from('H', f.read(2))[0]
        e_phentsize = struct.unpack_from('H', f.read(2))[0]
        e_phnum = struct.unpack_from('H', f.read(2))[0]
        e_shentsize = struct.unpack_from('H', f.read(2))[0]
        e_shnum = struct.unpack_from('H', f.read(2))[0]
        e_shstrndx = struct.unpack_from('H', f.read(2))[0]

        sections = {}
        print()

        f.seek(e_shoff)
        for i in range(e_shnum):
            sh_name = struct.unpack_from('I', f.read(4))[0]
            sh_type = struct.unpack_from('I', f.read(4))[0]
            sh_flags = struct.unpack_from('I', f.read(4))[0] if size == '32' else struct.unpack_from('Q', f.read(8))[0]
            sh_addr = struct.unpack_from('I' if size == '32' else 'Q', f.read(4 if size == '32' else 8))[0]
            sh_offset = struct.unpack_from('I' if size == '32' else 'Q', f.read(4 if size == '32' else 8))[0]
            sh_size = struct.unpack_from('I' if size == '32' else 'Q', f.read(4 if size == '32' else 8))[0]
            sh_link = struct.unpack_from('I', f.read(4))[0]
            sh_info = struct.unpack_from('I', f.read(4))[0]
            sh_addralign = struct.unpack_from('I' if size == '32' else 'Q', f.read(4 if size == '32' else 8))[0]
            sh_entsize = struct.unpack_from('I' if size == '32' else 'Q', f.read(4 if size == '32' else 8))[0]

            sections[i] = {
                'sh_name': hex(sh_name),
                'sh_type': hex(sh_type),
                'sh_flags': hex(sh_flags),
                'sh_addr': hex(sh_addr),
                'sh_offset': hex(sh_offset),
                'sh_size': hex(sh_size),
                'sh_link': hex(sh_link),
                'sh_info': hex(sh_info),
                'sh_addralign': hex(sh_addralign),
                'sh_entsize': hex(sh_entsize)
            }


        for v in sections.values():
            v['raw_name'] = get_section_name_from_sh_name(int(v['sh_name'],16) + int(sections[e_shstrndx].get("sh_offset"),16), f)

        if sections:
            del sections[0]

        reindexed_sections = {}

        if sections:
            for section in sections.values():
                reindexed_sections[section['raw_name']] = section


        return {
            'ei_class': hex(ei_class),
            'ei_data': hex(ei_data),
            'ei_version': hex(ei_version),
            'ei_osabi': hex(ei_osabi),
            'ei_abiversion': hex(ei_abiversion),
            'e_type': hex(e_type),
            'e_machine': hex(e_machine),
            'e_version': hex(e_version),
            'e_entry': hex(e_entry),
            'e_phoff': hex(e_phoff),
            'e_shoff': hex(e_shoff),
            'e_flags': hex(e_flags),
            'e_ehsize': hex(e_ehsize),
            'e_phentsize': hex(e_phentsize),
            'e_phnum': hex(e_phnum),
            'e_shentsize': hex(e_shentsize),
            'e_shnum': hex(e_shnum),
            'e_shstrndx': hex(e_shstrndx),
            'sections': reindexed_sections
        }

def get_section_name_from_sh_name(sh_name, file_ptr):
    file_ptr.seek(sh_name)
    name = ''
    while True:
        c = file_ptr.read(1)
        if c == b'\x00':
            break
        name += c.decode('utf-8')
    return name

def print_section_bytes(file, section_name, parse_output):
    with open(file, 'rb') as f:
        section = parse_output.get('sections').get(section_name)

        if not section:
            print(f'Section {section_name} not found')
            return

        f.seek(int(section['sh_offset'], 16))
        content = f.read(int(section['sh_size'], 16))
        return ' '.join([hex(c)[2:].zfill(2) for c in content])


if __name__ == "__main__":
    import json, argparse
    parser = argparse.ArgumentParser(description='PE file parser')
    parser.add_argument('-f', '--file', help='ELF file to parse', type=str, required=True)
    parser.add_argument('-p', '--print_section_bytes', type=str, required=False)
    args = parser.parse_args()

    parsed_elf = parse_elf(args.file)

    print(json.dumps(parsed_elf, indent=4))


    if args.print_section_bytes:
        print("#####################")
        print("Section bytes for section: " + args.print_section_bytes)
        print(print_section_bytes(args.file, args.print_section_bytes, parsed_elf))

