import pelfy._main as _main
import glob


def test_symbol_relocations() -> None:
    """symbol.relocations (cached, grouped by section) must match a
    filter over all relocations of the file"""
    file_list = glob.glob('tests/obj/*.o')
    assert file_list, "No test object files found"
    for path in file_list:
        elf = _main.open_elf_file(path)
        all_relocations = list(elf.get_relocations())

        for sym in elf.symbols:
            if not sym.section or sym.section.type != 'SHT_PROGBITS':
                continue
            expected = [r for r in all_relocations
                        if r.target_section is sym.section and
                        0 <= r['r_offset'] - sym.offset_in_section < sym['st_size']]

            relocations = sym.relocations
            assert [r.fields for r in relocations] == [r.fields for r in expected], (path, sym.name)

            # Repeated access returns the same relocations, the returned list
            # does not expose the cache
            relocations._data.clear()
            assert [r.fields for r in sym.relocations] == [r.fields for r in expected], (path, sym.name)


if __name__ == '__main__':
    test_symbol_relocations()
