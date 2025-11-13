import pelfy._main as _main
import glob


def known_name(text: str) -> bool:
    return not text.isnumeric() and not text.startswith('0x')


def test_simple_c() -> None:
    file_list = glob.glob('tests/obj/*.o')
    assert file_list, "No test object files found"
    for path in file_list:
        print(f'Open {path}...')
        elf = _main.open_elf_file(path)

        print(elf)
        print(elf.sections)
        print(elf.symbols)
        print(elf.code_relocations)
        print('\n')

        section_count = 0
        assert elf.sections
        for section in elf.sections:
            assert known_name(section.description), f"Section type {section.type} for {elf.architecture} in {path} is unknown."

            for sym in section.symbols:
                assert known_name(sym.info), f"Symbol info {sym.info} for {elf.architecture} in {path} is unknown."
                section_count += 1

        assert section_count > 2

        assert elf.symbols
        for sym in elf.symbols:
            assert known_name(sym.info), f"Symbol info {sym.info} for {elf.architecture} in {path} is unknown."

        assert elf.get_relocations()
        for reloc in elf.get_relocations():
            assert known_name(reloc.type), f"Relocation type {reloc.type} for {elf.architecture} in {path} is unknown."

        assert 'imageWidth' in elf.objects or 'read_float_ret' in elf.objects, path
        assert 'leet456456456n4ghn4hf56n4f' not in elf.objects
        assert 0 in elf.objects
        assert 1000 not in elf.objects
        assert elf.objects[0] in elf.symbols
        assert elf.objects[0] not in elf.functions


if __name__ == '__main__':
    test_simple_c()
