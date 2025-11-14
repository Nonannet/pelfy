"""Pelfy is an ELF parser for parsing header fields, sections, symbols and relocations.

Typical usage example:

    elf = pelfy.open_elf_file('obj/test-c-riscv64-linux-gnu-gcc-12-O3.o')
    print(elf.sections)
"""

from . import _fields_data as fdat
from . import _output_formatter
from typing import TypeVar, Literal, Iterable, Generic, Iterator, Generator, Optional, Union

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

    Attributes:
        file: Points to the parent ELF file object.
        name: Name of the symbol
        section: section where the symbol data is placed
        index: Absolut index in the symbol table
        info: Type of the symbol
        description: Description of the symbol type
        stb: visibility of the symbol (local, global, etc.)
        stb_description: Description of the symbol visibility
        fields: All symbol header fields as dict
    """

    def __init__(self, file: 'elf_file', fields: dict[str, int], index: int):
        """
        Initializes ELF symbol instance

        Args:
            file: ELF file object
            fields: symbol header fields
            index: Absolut index in the symbol table
        """
        self.fields = fields
        self.file = file

        if file.string_table_section:
            self.name = file.read_string(file.string_table_section['sh_offset'] + fields['st_name'])
        else:
            self.name = ''

        self.section: Optional[elf_section] = self.file.sections[self['st_shndx']] if self['st_shndx'] < len(self.file.sections) else None

        self.index = index

        self.info, self.description = fdat.st_info_values[fields['st_info'] & 0x0F]
        self.stb, self.stb_description = fdat.stb_values[fields['st_info'] >> 4]

    @property
    def data(self) -> bytes:
        """Returns the binary data the symbol is pointing to.
        The offset in the ELF file is calculated by:
        sections[symbol.st_shndx].sh_offset + symbol.st_value
        """
        assert self.section, 'This symbol is not associated to a data section'
        if self.section.type == 'SHT_NOBITS':
            return b'\x00' * self['st_size']
        else:
            offset = self.section['sh_offset'] + self['st_value']
            return self.file.read_bytes(offset, self['st_size'])

    @property
    def data_hex(self) -> str:
        """Returns the binary data the symbol is pointing to as hex string.
        """
        return ' '.join(f'{d:02X}' for d in self.data)

    @property
    def relocations(self) -> 'relocation_list':
        """Relocations that are pointing to this symbol.
        The symbol section must be of type SHT_PROGBITS (program code). Therefore
        this property returns typically all relocations that will be
        applied to the function represented by the symbol.
        """
        ret: list[elf_relocation] = list()
        assert self.section and self.section.type == 'SHT_PROGBITS'
        for reloc in self.file.get_relocations():
            if reloc.target_section == self.section:
                offset = reloc['r_offset'] - self['st_value']
                if 0 <= offset < self['st_size']:
                    ret.append(reloc)
        return relocation_list(ret)

    def __getitem__(self, key: Union[str, int]) -> int:
        if isinstance(key, str):
            assert key in self.fields, f'Unknown field name: {key}'
            return self.fields[key]
        else:
            return list(self.fields.values())[key]

    def __repr__(self) -> str:
        return f'index             {self.index}\n' +\
               f'name              {self.name}\n' +\
               f'stb               {self.stb} ({self.stb_description})\n' +\
               f'info              {self.info} ({self.description})\n' +\
               '\n'.join(f"{k:18} {v:4} {fdat.symbol_fields[k]}" for k, v in self.fields.items()) + '\n'


class elf_section():
    """A class for representing data of an ELF section

    Attributes:
        file: Points to the parent ELF file object.
        name: Name of the section
        index: Absolut index of the section
        type: Type of the section
        description: Description of the section type
        fields: All symbol header fields as dict
    """
    def __init__(self, file: 'elf_file', fields: dict[str, int], name: str, index: int):
        """Initializes an ELF section instance

        Args:
            file: ELF file object
            fields: Section header fields
            name: Name of the section
            index: Absolut index in the symbol table
        """
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

    @property
    def data(self) -> bytes:
        """Returns the binary data from the section.
        The offset in the ELF file is given by: section.sh_offset
        """
        if self.type == 'SHT_NOBITS':
            return b'\x00' * self['sh_size']
        else:
            return self.file.read_bytes(self['sh_offset'], self['sh_size'])

    @property
    def symbols(self) -> 'symbol_list':
        """All ELF symbols associated with this section
        """
        return symbol_list(self.file.list_symbols(self.index))

    @property
    def data_hex(self) -> str:
        """Returns the binary data from the section as hex string.
        """
        return ' '.join(f'{d:02X}' for d in self.data)

    def __getitem__(self, key: Union[str, int]) -> int:
        if isinstance(key, str):
            assert key in self.fields, f'Unknown field name: {key}'
            return self.fields[key]
        else:
            return list(self.fields.values())[key]

    def __repr__(self) -> str:
        return f'index             {self.index}\n' +\
               f'name              {self.name}\n' +\
               f'type              {self.type} ({self.description})\n' +\
               '\n'.join(f"{k:18} {v:4} {fdat.section_header[k]['description']}" for k, v in self.fields.items()) + '\n'


class elf_relocation():
    """A class for representing data of a relocation

    Attributes:
        file: Points to the parent ELF file object.
        index: Absolut index of the relocation in the associated relocation section
        symbol: Symbol to relocate
        type: Type of the relocation
        calculation: Description of the relocation calculation
        bits: number ob bits to patch by the relocation
        target_section: Pointing to the section where this relocation applies to
        fields: All relocation header fields as dict
    """
    def __init__(self, file: 'elf_file', fields: dict[str, int], symbol_index: int,
                 relocation_type: int, sh_info: int, index: int):
        """Initializes a ELF relocation instance

        Args:
            file: ELF file object
            fields: Relocation header fields
            symbol_index: Index of the symbol to relocate in the symbol table
            relocation_type: Type of the relocation (numeric)
            sh_info: Index of the section this relocation applies to
            index: Absolut index of the relocation in the associated relocation section
        """
        self.fields = fields
        self.file = file
        self.index = index
        self.symbol = file.symbols[symbol_index]
        reloc_types = fdat.relocation_table_types.get(file.architecture)
        if reloc_types and relocation_type in reloc_types:
            self.type = reloc_types[relocation_type][0]
            self.bits = reloc_types[relocation_type][1]
            self.calculation = reloc_types[relocation_type][2]
        else:
            self.type = str(relocation_type)
            self.bits = 0
            self.calculation = ''
        self.target_section: elf_section = file.sections[sh_info]

    def __getitem__(self, key: Union[str, int]) -> int:
        if isinstance(key, str):
            assert key in self.fields, f'Unknown field name: {key}'
            return self.fields[key]
        else:
            return list(self.fields.values())[key]

    def __repr__(self) -> str:
        return f'index                {self.symbol.index}\n' +\
               f'symbol               {self.symbol.name}\n' +\
               f'relocation type      {self.type}\n' +\
               f'calculation          {self.calculation}\n' +\
               f'bits                 {self.bits}\n' +\
               '\n'.join(f'{k:18} {v:4}' for k, v in self.fields.items()) + '\n'


class elf_list(Generic[_T]):
    """A generic class for representing a list of ELF data items

    Args:
        data: Iterable of ELF data items
    """
    def __init__(self, data: Iterable[_T]):
        self._data = list(data)

    def __getitem__(self, key: Union[str, int]) -> _T:
        if isinstance(key, str):
            elements = [el for el in self._data if getattr(el, 'name', '') == key]
            assert elements, f'Unknown name: {key}'
            return elements[0]
        else:
            return self._data.__getitem__(key)

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self) -> Iterator[_T]:
        return iter(self._data)

    def __contains__(self, item: Union[str, int, _T]) -> bool:
        if isinstance(item, str):
            return any(getattr(el, 'name', '') == item for el in self._data)
        elif isinstance(item, int):
            return 0 <= item < len(self._data)
        else:
            return item in self._data

    def _compact_table(self) -> tuple[list[str], list[list[Union[str, int]]], list[str]]:
        return [], [[]], []

    def _repr_table(self, format: _output_formatter.table_format, raw_data: bool = False) -> str:
        if raw_data and len(self):
            table_dict: list[dict[str, int]] = [el.__dict__.get('fields', {' ': 0}) for el in self]
            columns = list(table_dict[0].keys())
            data: list[list[Union[str, int]]] = [list(el.values()) for el in table_dict]
            radj = columns
        else:
            columns, data, radj = self._compact_table()
        return _output_formatter.generate_table(data, columns, right_adj_col=radj, format=format)

    def to_dict_list(self) -> list[dict[str, Union[str, int]]]:
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

    def __repr__(self) -> str:
        return self._repr_table('text')

    def _repr_html_(self) -> str:
        return self._repr_table('html')

    def _repr_markdown_(self) -> str:
        return self._repr_table('markdown')


class section_list(elf_list[elf_section]):
    """A class for representing a list of ELF section
    """
    def _compact_table(self) -> tuple[list[str], list[list[Union[str, int]]], list[str]]:
        columns = ['index', 'name', 'type', 'description']
        data: list[list[Union[str, int]]] = [[item.index, item.name, item.type,
                                             item.description] for item in self]
        return columns, data, ['index']


class symbol_list(elf_list[elf_symbol]):
    """A class for representing a list of ELF symbols
    """
    def _compact_table(self) -> tuple[list[str], list[list[Union[str, int]]], list[str]]:
        columns = ['index', 'name', 'info', 'size', 'stb', 'section', 'description']
        data: list[list[Union[str, int]]] = [[item.index, item.name, item.info, item.fields['st_size'],
                                              item.stb, item.section.name if item.section else '', item.description] for item in self]
        return columns, data, ['index', 'size']


class relocation_list(elf_list[elf_relocation]):
    """A class for representing a list of ELF relocations
    """
    def _compact_table(self) -> tuple[list[str], list[list[Union[str, int]]], list[str]]:
        columns = ['index', 'symbol name', 'type', 'calculation', 'bits']
        data: list[list[Union[str, int]]] = [[item.index, item.symbol.name, item.type,
                                              item.calculation, item.bits] for item in self]
        return columns, data, ['index', 'bits']


class elf_file:
    """A class for representing data of an ELF file in a structured form

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
    def __init__(self, data: Union[bytes, bytearray]):
        """Initializes an ELF file instance

        Args:
            data: binary ELF data
        """
        assert isinstance(data, (bytes, bytearray)), 'Binary ELF data must be provided as bytes or bytearray.'
        self._data = bytes(data)

        # Defaults required for function _read_int_from_elf_field
        self.bit_width = 32
        self.byteorder: Literal['little', 'big'] = 'little'

        assert self._read_bytes_from_elf_field('e_ident[EI_MAG]') == b'\x7fELF', 'Not an ELF file'

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

        self.symbols = symbol_list(self.list_symbols())

        self.functions = symbol_list(s for s in self.symbols if s.info == 'STT_FUNC')
        self.objects = symbol_list(s for s in self.symbols if s.info == 'STT_OBJECT')

        self.code_relocations = self.get_relocations(['.rela.text', '.rel.text'])

    def _list_sections(self) -> Generator[dict[str, int], None, None]:
        for i in range(self.fields['e_shnum']):
            offs = self.fields['e_shoff'] + i * self.fields['e_shentsize']
            yield {fn: self._read_from_sh_field(offs, fn) for fn in fdat.section_header.keys()}

    def list_symbols(self, section_index: Optional[int] = None) -> Generator[elf_symbol, None, None]:
        """List ELF symbols.

        Args:
            section_index: If provided, only symbols from the specified section are returned.

        Returns:
            List of ELF symbols
        """
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

                if section_index is None or section_index == ret['st_shndx']:
                    yield elf_symbol(self, ret, j)

    def get_relocations(self, reloc_section: Optional[Union[elf_section, str, list[str]]] = None) -> relocation_list:
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

    def _list_relocations(self, sh: elf_section) -> Generator[elf_relocation, None, None]:
        """List relocations for a elf_section.

        Args:
            elf_section: Specifies the relocation section from which the
                relocations should be listed.

        Returns:
            Relocations from specified elf_section
        """
        sh_offset = sh['sh_offset']
        for i, el_off in enumerate(range(sh_offset, sh['sh_size'] + sh_offset, sh['sh_entsize'])):
            ret: dict[str, int] = dict()

            if self.bit_width == 32:
                r_offset = self.read_int(el_off, 4)
                r_info = self.read_int(el_off + 4, 4)
                symbol_index = r_info >> 8
                relocation_type = r_info & 0xFF
                ret['r_addend'] = self.read_int(el_off + 8, 4, True) \
                    if sh.type == 'SHT_RELA' else self._get_rel_32bit_addend(r_offset, sh)
            elif self.bit_width == 64:
                r_offset = self.read_int(el_off, 8)
                r_info = self.read_int(el_off + 8, 8)
                symbol_index = r_info >> 32
                relocation_type = r_info & 0xFFFFFFFF
                ret['r_addend'] = self.read_int(el_off + 16, 8, True) \
                    if sh.type == 'SHT_RELA' else self._get_rel_32bit_addend(r_offset, sh)
            else:
                raise NotImplementedError(f"{self.bit_width} bit is not supported")

            ret['r_offset'] = r_offset
            ret['r_info'] = r_info
            yield elf_relocation(self, ret, symbol_index, relocation_type, sh['sh_info'], i)

    def _get_rel_32bit_addend(self, r_offset: int, reloc_section: elf_section) -> int:
        sh = self.sections[reloc_section['sh_info']]
        return self.read_int(r_offset + sh['sh_offset'], 4, True)

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

    def __repr__(self) -> str:
        hf_list = ((hf, self.fields[hf['field_name']]) for hf in fdat.elf_header_field.values())
        return '\n'.join(f"{hf['field_name']:24} {v:4}   {hf['description']}" for hf, v in hf_list) + '\n'

    def __getitem__(self, key: str) -> int:
        assert key in self.fields, f'Unknown field name: {key}'
        return self.fields[key]
