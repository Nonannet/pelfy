from . import fields_data as fdat
from . import output_formatter
from typing import TypeVar, Literal, Iterable, Generic

_T = TypeVar('_T')


def open_elf_file(file_path: str) -> 'elf_file':
    """Reads ELF data from file

    Args:
        file_path: path of the ELF file

    Returns:
        elf_file object
    """
    with open(file_path, mode='rb') as f:
        return elf_file(f.read())


class elf_symbol():
    """A class for representing data of an ELF symbol

    Args:
        file: ELF file object

        fields: symbol header fields

        index: Absolut index in the symbol table

    Attributes:
        file: Points to the parent ELF file object.

        name: Name of the symbol

        index: Absolut index in the symbol table

        info: Type of the symbol

        description: Description of the symbol type

        stb: visibility of the symbol (local, global, etc.)

        stb_description: Description of the symbol visibility

        fields: All symbol header fields as dict
    """

    def __init__(self, file: 'elf_file', fields: dict[str, int], index: int):
        self.fields = fields
        self.file = file

        if file.string_table_section:
            self.name = file.read_string(file.string_table_section['sh_offset'] + fields['st_name'])
        else:
            self.name = ''

        self.index = index

        self.info, self.description = fdat.st_info_values[fields['st_info'] & 0x0F]
        self.stb, self.stb_description = fdat.stb_values[fields['st_info'] >> 4]

    def read_data(self) -> bytes:
        """Returns the binary data the symbol is pointing to.
        The offset in the ELF file is calculated by:
        sections[symbol.st_shndx].sh_offset + symbol.st_value

        Returns:
            Symbol data
        """
        offset = self.file.sections[self['st_shndx']]['sh_offset'] + self['st_value']
        return self.file.read_bytes(offset, self['st_size'])

    def read_data_hex(self) -> str:
        return ' '.join(f'{d:02X}' for d in self.read_data())

    def get_relocations(self) -> 'relocation_list':
        """List all relocations that are pointing to this symbol.
        The symbol must be of type SHT_PROGBITS (program code). Therefore
        this function lists typically all relocations that will be
        applied to the function represented by the symbol.

        Returns:
            List of relocations
        """
        ret: list[elf_relocation] = list()
        section = self.file.sections[self.fields['st_shndx']]
        assert section.type == 'SHT_PROGBITS'
        for reloc in self.file.get_relocations():
            if reloc.target_section == section:
                offset = reloc['r_offset'] - self['st_value']
                if 0 <= offset < self['st_size']:
                    ret.append(reloc)
        return relocation_list(ret)

    def __getitem__(self, key: str | int):
        if isinstance(key, str):
            assert key in self.fields, f'Unknown field name: {key}'
            return self.fields[key]
        else:
            return list(self.fields.values())[key]

    def __repr__(self):
        return f'index             {self.index}\n' +\
               f'name              {self.name}\n' +\
               f'stb               {self.stb} ({self.stb_description})\n' +\
               f'info              {self.info} ({self.description})\n' +\
               '\n'.join(f'{k:18} {v:4}' for k, v in self.fields.items()) + '\n'


class elf_section():
    """A class for representing data of an ELF section

    Args:
        file: ELF file object

        fields: Section header fields

        name: Name of the section

        index: Absolut index in the symbol table

    Attributes:
        file: Points to the parent ELF file object.

        name: Name of the section

        index: Absolut index of the section

        type: Type of the section

        description: Description of the section type

        fields: All symbol header fields as dict
    """
    def __init__(self, file: 'elf_file', fields: dict[str, int], name: str, index: int):
        self.fields = fields
        self.file = file
        self.index = index
        self.name = name

        if fields['sh_type'] > 0x60000000:
            # Range for OS, compiler and application specific types
            self.description = [v for k, v in fdat.section_header_types_ex.items() if k >= fields['sh_type']][0]
            self.type = str(hex(fields['sh_type']))
        elif fields['sh_type'] in fdat.section_header_types:
            self.type, self.description = fdat.section_header_types[fields['sh_type']]
        else:
            self.description = ''
            self.type = str(hex(fields['sh_type']))

    def read_data(self) -> bytes:
        """Returns the binary data from the section.
        The offset in the ELF file is given by: section.sh_offset

        Returns:
            Data of the section
        """
        return self.file.read_bytes(self['sh_offset'], self['sh_size'])

    def get_data_hex(self) -> str:
        data = self.file.read_bytes(self['sh_offset'], self['sh_size'])
        return ' '.join(f'{d:02X}' for d in data)

    def __getitem__(self, key: str | int):
        if isinstance(key, str):
            assert key in self.fields, f'Unknown field name: {key}'
            return self.fields[key]
        else:
            return list(self.fields.values())[key]

    def __repr__(self):
        return f'index             {self.index}\n' +\
               f'name              {self.name}\n' +\
               f'type              {self.type} ({self.description})\n' +\
               '\n'.join(f"{k:18} {v:4} {fdat.section_header[k]['description']}" for k, v in self.fields.items()) + '\n'


class elf_relocation():
    """A class for representing data of a relocation

    Args:
        file: ELF file object

        fields: Relocation header fields

        symbol_index: Index of the symbol to relocate in the symbol table

        relocation_type: Type of the relocation (numeric)

        sh_info: Index of the section this relocation applies to

        index: Absolut index of the relocation in the associated relocation section

    Attributes:
        file: Points to the parent ELF file object.

        index: Absolut index of the relocation the associated relocation section

        type: Type of the relocation

        calculation: Description of the relocation calculation

        target_section: Pointing to the section that is relocation applies to

        fields: All relocation header fields as dict
    """
    def __init__(self, file: 'elf_file', fields: dict[str, int], symbol_index: int,
                 relocation_type: int, sh_info: int, index: int):
        self.fields = fields
        self.file = file
        self.index = index
        self.symbol = file.symbols[symbol_index]
        reloc_types = fdat.relocation_table_types.get(file.architecture)
        if reloc_types and relocation_type in reloc_types:
            self.calculation = reloc_types[relocation_type][2]
            self.type = reloc_types[relocation_type][0]
        else:
            self.calculation = ''
            self.type = str(relocation_type)
        self.target_section = file.sections[sh_info]

    def __getitem__(self, key: str | int):
        if isinstance(key, str):
            assert key in self.fields, f'Unknown field name: {key}'
            return self.fields[key]
        else:
            return list(self.fields.values())[key]

    def __repr__(self):
        return f'index                {self.symbol.index}\n' +\
               f'symbol               {self.symbol.name}\n' +\
               f'relocation type      {self.type} ({self.calculation})\n' +\
               '\n'.join(f'{k:18} {v:4}' for k, v in self.fields.items()) + '\n'


class elf_list(Generic[_T]):
    """A generic class for representing a list of ELF data items

    Args:
        data: Iterable of ELF data items
    """
    def __init__(self, data: Iterable[_T]):
        self._data = list(data)

    def __getitem__(self, key: int | str):
        if isinstance(key, str):
            elements = [el for el in self._data if getattr(el, 'name', '') == key]
            assert elements, f'Unknown name: {key}'
            return elements[0]
        else:
            return self._data.__getitem__(key)

    def __len__(self):
        return len(self._data)

    def __iter__(self):
        return iter(self._data)

    def _compact_table(self) -> tuple[list[str], list[list[str | int]], list[str]]:
        return [], [[]], []

    def _repr_table(self, format: output_formatter.table_format, raw_data: bool = False):
        if raw_data and len(self):
            table_dict: list[dict[str, int]] = [el.__dict__.get('fields', {' ': 0}) for el in self]
            columns = list(table_dict[0].keys())
            data: list[list[str | int]] = [list(el.values()) for el in table_dict]
            radj = columns
        else:
            columns, data, radj = self._compact_table()
        return output_formatter.generate_table(data, columns, right_adj_col=radj, format=format)

    def to_dict_list(self) -> list[dict[str, str | int]]:
        """Exporting the ELF item data table to a list of dicts. It can be used with pandas:
        df = pandas.DataFrame(elements.to_dict_list())

        Returns:
            Table data
        """
        columns, data, _ = self._compact_table()
        return [{k: v for k, v in zip(columns, row)} for row in data]

    def to_html(self) -> str:
        """Exporting the ELF item data table to HTML.

        Returns:
            HTML table
        """
        return self._repr_table('html')

    def to_markdown(self) -> str:
        """Exporting the ELF item data table to markdown.

        Returns:
            Markdown table
        """
        return self._repr_table('markdown')

    def __repr__(self):
        return self._repr_table('text')

    def _repr_html_(self):
        return self._repr_table('html')


class section_list(elf_list[elf_section]):
    """A class for representing a list of ELF section
    """
    def _compact_table(self):
        columns = ['index', 'name', 'type', 'description']
        data: list[list[str | int]] = [[item.index, item.name, item.type,
                                       item.description] for item in self]
        return columns, data, ['index']


class symbol_list(elf_list[elf_symbol]):
    """A class for representing a list of ELF symbols
    """
    def _compact_table(self):
        columns = ['index', 'name', 'info', 'size', 'stb', 'description']
        data: list[list[str | int]] = [[item.index, item.name, item.info, item.fields['st_size'],
                                       item.stb, item.description] for item in self]
        return columns, data, ['index', 'size']


class relocation_list(elf_list[elf_relocation]):
    """A class for representing a list of ELF relocations
    """
    def _compact_table(self):
        columns = ['index', 'symbol name', 'type', 'calculation']
        data: list[list[str | int]] = [[item.index, item.symbol.name, item.type,
                                        item.calculation] for item in self]
        return columns, data, ['index']


class elf_file:
    """A class for representing data of an ELF file in a structured form

    Args:
        data: binary ELF data

    Attributes:
        byteorder: Byte order of the architecture 'little' or 'big'
            (based on e_ident[EI_DATA])

        bit_width: Bit with of the architecture: 32 or 64 (based on
            e_ident[EI_CLASS])

        architecture: Name of the architecture (based on e_machine)

        fields: All ELF header fields as dict

        sections: A list of all ELF sections

        symbols: A list of all ELF symbols

        functions: A list of all function symbols (STT_FUNC)

        objects: A list of all variable/object symbols (STT_OBJECT)

        code_relocations: A list of all code relocations (.rela.text and .rel.text)

        symbol_table_section: The symbol table section (first section with
            the type SHT_SYMTAB)

        string_table_section: The string table section (first section with
            the name .strtab)
    """
    def __init__(self, data: bytes):
        self._data = data

        # Defaults required for function _read_int_from_elf_field
        self.bit_width = 32
        self.byteorder: Literal['little', 'big'] = 'little'

        assert self._read_bytes_from_elf_field('e_ident[EI_MAG]') == bytes([0x7F, 0x45, 0x4c, 0x46]), 'Not an ELF file'

        self.bit_width = {1: 32, 2: 64}[self._read_int_from_elf_field('e_ident[EI_CLASS]')]

        byte_order = self._read_int_from_elf_field('e_ident[EI_DATA]')
        assert byte_order in [1, 2], 'Invalid byte order value e_ident[EI_DATA]'
        self.byteorder = 'little' if byte_order == 1 else 'big'

        self.fields = {fn: self._read_int_from_elf_field(fn) for fn in fdat.elf_header_field.keys()}

        arch_entr = fdat.e_machine_dict.get(self.fields['e_machine'])
        self.architecture = arch_entr[0] if arch_entr else str(self.fields['e_machine'])

        section_data = list(self._list_sections())
        name_addr: dict[str, int] = section_data[self.fields['e_shstrndx']] if section_data else dict()
        section_names = (self.read_string(name_addr['sh_offset'] + f['sh_name']) for f in section_data)

        self.sections = section_list(elf_section(self, sd, sn, i)
                                     for i, (sd, sn) in enumerate(zip(section_data, section_names)))

        ret_sections = [sh for sh in self.sections if sh.type == 'SHT_SYMTAB']
        self.symbol_table_section = ret_sections[0] if ret_sections else None

        ret_sections = [sh for sh in self.sections if sh.name == '.strtab']
        self.string_table_section = ret_sections[0] if ret_sections else None

        self.symbols = symbol_list(self._list_symbols())

        self.functions = symbol_list(s for s in self.symbols if s.info == 'STT_FUNC')
        self.objects = symbol_list(s for s in self.symbols if s.info == 'STT_OBJECT')

        self.code_relocations = self.get_relocations(['.rela.text', '.rel.text'])

    def _list_sections(self):
        for i in range(self.fields['e_shnum']):
            offs = self.fields['e_shoff'] + i * self.fields['e_shentsize']
            yield {fn: self._read_from_sh_field(offs, fn) for fn in fdat.section_header.keys()}

    def _list_symbols(self):
        if self.symbol_table_section:
            offs = self.symbol_table_section['sh_offset']

            for j, i in enumerate(range(offs, self.symbol_table_section['sh_size'] + offs, self.symbol_table_section['sh_entsize'])):
                ret = {'st_name': self.read_int(i, 4)}

                if self.bit_width == 32:
                    ret['st_value'] = self.read_int(i + 4, 4)
                    ret['st_size'] = self.read_int(i + 8, 4)
                    ret['st_info'] = self.read_int(i + 12, 1)
                    ret['st_other'] = self.read_int(i + 13, 1)
                    ret['st_shndx'] = self.read_int(i + 14, 2)
                elif self.bit_width == 64:
                    ret['st_info'] = self.read_int(i + 4, 1)
                    ret['st_other'] = self.read_int(i + 5, 1)
                    ret['st_shndx'] = self.read_int(i + 6, 2)
                    ret['st_value'] = self.read_int(i + 8, 8)
                    ret['st_size'] = self.read_int(i + 16, 8)

                yield elf_symbol(self, ret, j)

    def get_relocations(self, reloc_section: elf_section | str | list[str] | None = None) -> relocation_list:
        """List relocations.

        Args:
            reloc_section: Specifies the relocation section from which the
                relocations should be listed. It can be provided as
                elf_section object or by its name. If not provided
                (reloc_section=None) relocations from all relocation
                sections are returned.

        Returns:
            List of relocations
        """
        if isinstance(reloc_section, elf_section):
            assert reloc_section.type in ('SHT_REL', 'SHT_RELA'), f'{reloc_section.name} is not a relocation section'
            return relocation_list(self._list_relocations(reloc_section))
        else:
            relocations: list[elf_relocation] = list()
            for sh in self.sections:
                if sh.type in ('SHT_REL', 'SHT_RELA'):
                    if reloc_section is None or \
                            (isinstance(reloc_section, str) and sh.name == reloc_section) or \
                            (isinstance(reloc_section, list) and sh.name in reloc_section):
                        relocations += relocation_list(self._list_relocations(sh))

            return relocation_list(relocations)

    def _list_relocations(self, sh: elf_section):
        """List relocations for a elf_section.

        Args:
            elf_section: Specifies the relocation section from which the
                relocations should be listed.

        Returns:
            Relocations from specified elf_section
        """
        offs = sh['sh_offset']
        for i, el_off in enumerate(range(offs, sh['sh_size'] + offs, sh['sh_entsize'])):
            ret: dict[str, int] = dict()

            if self.bit_width == 32:
                ret['r_offset'] = self.read_int(el_off, 4)
                r_info = self.read_int(el_off + 4, 4)
                ret['r_info'] = r_info
                ret['r_addend'] = self.read_int(el_off + 8, 4, True) if sh.type == 'SHT_RELA' else 0
                yield elf_relocation(self, ret, r_info >> 8, r_info & 0xFF, sh['sh_info'], i)
            elif self.bit_width == 64:
                ret['r_offset'] = self.read_int(el_off, 8)
                r_info = self.read_int(el_off + 8, 8)
                ret['r_info'] = r_info
                ret['r_addend'] = self.read_int(el_off + 16, 8, True) if sh.type == 'SHT_RELA' else 0
                yield elf_relocation(self, ret, r_info >> 32, r_info & 0xFFFFFFFF, sh['sh_info'], i)

    def read_bytes(self, offset: int, num_bytes: int) -> bytes:
        """Read bytes from ELF file.

        Args:
            offset: Specify first byte relative to the start of
                the ELF file.

            num_bytes: Specify the number of bytes to read.

        Returns:
            Binary data as bytes
        """
        return self._data[offset:offset + num_bytes]

    def read_int(self, offset: int, num_bytes: int, signed: bool = False) -> int:
        """Read an integer from the ELF file. Byte order is
        selected according to the architecture (e_ident[EI_DATA]).

        Args:
            offset: Specify first byte of the integer relative to
                the start of the ELF file.

            num_bytes: Specify the size of the integer in bytes.

            signed: Select if the integer is a signed integer.

        Returns:
            Integer value
        """
        return int.from_bytes(self._data[offset:offset + num_bytes], self.byteorder, signed=signed)

    # def int_to_bytes(self, value: int, num_bytes: int = 4, signed: bool = False) -> int:
    #     return value.to_bytes(length=num_bytes, byteorder=self.byteorder, signed=signed)

    def read_string(self, offset: int, encoding: str = 'utf-8') -> str:
        """Read a zero-terminated text string from the ELF file.

        Args:
            offset: Specify first byte of the string relative to
                the start of the ELF file.

            encoding: Encoding used for text decoding.

        Returns:
            Text string
        """
        str_end = self._data.find(b'\x00', offset)
        return self._data[offset:str_end].decode(encoding)

    def _read_int_from_elf_field(self, field_name: str) -> int:
        field = fdat.elf_header_field[field_name]
        offs = int(field[str(self.bit_width)], base=16)
        byte_len = int(field['size' + str(self.bit_width)])
        return self.read_int(offs, byte_len)

    def _read_bytes_from_elf_field(self, field_name: str) -> bytes:
        field = fdat.elf_header_field[field_name]
        offs = int(field[str(self.bit_width)], base=16)
        byte_len = int(field['size' + str(self.bit_width)])
        return self.read_bytes(offs, byte_len)

    def _read_from_sh_field(self, offset: int, field_name: str) -> int:
        field = fdat.section_header[field_name]
        offs = int(field[str(self.bit_width)], base=16) + offset
        byte_len = int(field['size' + str(self.bit_width)])
        return self.read_int(offs, byte_len)

    def __repr__(self):
        hf_list = ((hf, self.fields[hf['field_name']]) for hf in fdat.elf_header_field.values())
        return '\n'.join(f"{hf['field_name']:24} {v:4}   {hf['description']}" for hf, v in hf_list) + '\n'

    def __getitem__(self, key: str):
        assert key in self.fields, f'Unknown field name: {key}'
        return self.fields[key]
