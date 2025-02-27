import pelfy
import glob


def known_name(text: str):
    return not text.isnumeric() and not text.startswith('0x')


def test_simple_c():
    file_list = glob.glob('tests/obj/*.o')
    assert file_list, "No test object files found"
    for path in file_list:
        print(f'Open {path}...')
        elf = pelfy.open_elf_file(path)

        print(elf)
        print(elf.sections)
        print(elf.symbols)
        print(elf.code_relocations)
        print('\n')

        for section in elf.sections:
            assert known_name(section.description), f"Section type {section.type} for {elf.architecture} in {path} is unknown."

        for sym in elf.symbols:
            assert known_name(sym.info), f"Symbol info {sym.info} for {elf.architecture} in {path} is unknown."

        for reloc in elf.get_relocations():
            assert known_name(reloc.type), f"Relocation type {reloc.type} for {elf.architecture} in {path} is unknown."


if __name__ == '__main__':
    test_simple_c()
