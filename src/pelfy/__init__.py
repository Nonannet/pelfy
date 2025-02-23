from . import fields_data as fdat
from . import format_output as fout
from typing import TypeVar, Literal, Iterable, Generic

T = TypeVar('T')

def open_elf_file(file_path: str):
    return elf_file(file_path)

class elf_symbol():
    def __init__(self, file: 'elf_file', fields: dict[str, int], index: int):
        self.fields = fields
        self.file = file

        if file.string_table:
            self.name = file.read_string(file.string_table['sh_offset'] + fields['st_name'])
        else:
            self.name = ''

        self.index = index

        st_info = fdat.st_info_values[fields['st_info'] & 0x0F]
        stb = fdat.stb_values[fields['st_info'] >> 4]
        
        self.stb = stb['name']
        self.description = st_info['description']
        self.info = st_info['name']

    def read_data(self) -> bytes:
        offset = self.file.sections[self['st_shndx']]['sh_offset'] + self['st_value']
        return self.file.read_bytes(offset, self['st_size'])

    def read_data_hex(self):
        return ' '.join(f'{d:02X}' for d in self.read_data())

    def get_relocations(self) -> 'relocation_list':
        ret: list[elf_relocation] = list()
        section = self.file.sections[self.fields['st_shndx']]
        assert section.type == 'SHT_PROGBITS'
        for reloc in self.file.get_relocations():
            if reloc.target_section == section:
                offset = reloc['r_offset'] - self['st_value']
                if 0 <= offset < self['st_size']:
                    ret.append(reloc)
        return relocation_list(ret)
    
    def __getitem__(self, key: str):
        assert key in self.fields, f'Unknown field name: {key}'
        return self.fields[key]

    def __repr__(self):
        stb = fdat.stb_values[self.fields['st_info'] >> 4]
        return f'index             {self.index}\n' +\
               f'name              {self.name}\n' +\
               f'stb               {self.stb} ({stb["description"]})\n' +\
               f'info              {self.info} ({self.description})\n' +\
                '\n'.join(f'{k:18} {v:4}' for k, v in self.fields.items()) + '\n'


class elf_section():
    def __init__(self, file: 'elf_file', fields: dict[str, int], name: str, index: int):
        self.fields = fields
        self.file = file
        self.index = index
        self.name = name

        assert fields['sh_type'] in fdat.section_header_types, f"Unknown section type: {hex(fields['sh_type'])}"
        self.description = fdat.section_header_types[fields['sh_type']]['description']
        self.type = fdat.section_header_types[fields['sh_type']]['name']

    def read_data(self):
        return self.file.read_bytes(self['sh_offset'], self['sh_size'])

    def read_data_hex(self):
        return ' '.join(f'{d:02X}' for d in self.read_data())
    
    def __getitem__(self, key: str):
        assert key in self.fields, f'Unknown field name: {key}'
        return self.fields[key]

    def __repr__(self):
        return f'index             {self.index}\n' +\
               f'name              {self.name}\n' +\
               f'type              {self.type} ({self.description})\n' +\
                '\n'.join(f"{k:18} {v:4} {fdat.section_header[k]['description']}" for k, v in self.fields.items()) + '\n'


class elf_relocation():
    def __init__(self, file: 'elf_file', fields: dict[str, int], symbol_index: int, relocation_type: int, sh_info: int):
        self.fields = fields
        self.file = file
        self.symbol = file.symbols[symbol_index]
        self.description = fdat.relocation_table_types[relocation_type]['description']
        self.type = fdat.relocation_table_types[relocation_type]['name']
        self.target_section = file.sections[sh_info]
            
    def __getitem__(self, key: str):
        assert key in self.fields, f'Unknown field name: {key}'
        return self.fields[key]

    def __repr__(self):
        return f'symbol               {self.symbol.name}\n' +\
               f'relocation type      {self.type} ({self.description})\n' +\
                '\n'.join(f'{k:18} {v:4}' for k, v in self.fields.items()) + '\n'


class elf_list(Generic[T]):
    def __init__(self, data: Iterable[T]):
        self._data = list(data)

    def __getitem__(self, key: int | str):
        if isinstance(key, str):
            elements = [el for el in self._data if getattr(el, 'name', '') == key]
            assert elements, f'Unknown name: {key}'
            return elements[0]
        #elif isinstance(key, slice):
        #    return elf_list(self._data.__getitem__(key))
        else:
            return self._data.__getitem__(key)

    def __iter__(self):
        """Return an iterator for the list."""
        return iter(self._data)

    def _repr_table(self, format: Literal['text', 'markdown', 'html']) -> str:
        return 'not implemented'
    
    def to_html(self):
        return self._repr_table('html')

    def to_markdown(self):
        return self._repr_table('markdown')

    def __repr__(self):
        return self._repr_table('text')
    
    def _repr_html_(self):
        return self._repr_table('html')


class section_list(elf_list[elf_section]):

    def _repr_table(self, format: Literal['text', 'markdown', 'html']):
         columns = ['index', 'name', 'type', 'description']
         data: list[list[str|int]] = [[item.index, item.name, item.type,
                                       item.description] for item in self]
         return fout.generate_table(data, columns, ['index'], format)


class symbol_list(elf_list[elf_symbol]):

    def _repr_table(self, format: Literal['text', 'markdown', 'html']):
         columns = ['index', 'name', 'info', 'size', 'stb', 'description']
         data: list[list[str|int]] = [[item.index, item.name, item.info, item.fields['st_size'],
                                       item.stb, item.description] for item in self]
         return fout.generate_table(data, columns, ['index', 'size'], format)


class relocation_list(elf_list[elf_relocation]):

    def _repr_table(self, format: Literal['text', 'markdown', 'html']):
         columns = ['symbol name', 'type', 'description']
         data: list[list[str|int]] = [[item.symbol.name, item.type, item.description] for item in self]
         return fout.generate_table(data, columns, format=format)


class elf_file:
    def __init__(self, file_path: str):
        with open(file_path, mode='rb') as f:
            self._data = f.read()

        #Defaults required for function _read_int_from_elf_field 
        self.bit_width = 32
        self.byteorder = 'little'

        assert self._read_bytes_from_elf_field('e_ident[EI_MAG]') == bytes([0x7F, 0x45, 0x4c, 0x46]), 'Not an ELF file'
        
        self.bit_width = {1: 32, 2: 64}[self._read_int_from_elf_field('e_ident[EI_CLASS]')]

        byte_order = self._read_int_from_elf_field('e_ident[EI_DATA]')
        assert byte_order in [1, 2], 'Invalid byte order value e_ident[EI_DATA]'
        self.byteorder: Literal['little', 'big'] = 'little' if byte_order == 1 else 'big'

        self.fields = {fn: self._read_int_from_elf_field(fn) for fn in fdat.elf_header_field.keys()}

        arch_entr = fdat.e_machine_dict.get(self.fields['e_machine'])
        self.architecture = arch_entr['name'] + ' - ' + arch_entr['description'] if arch_entr else 'Unknown'

        section_data = list(self._list_sections())
        name_addr: dict[str, int] = section_data[self.fields['e_shstrndx']] if section_data else dict()
        section_names = (self.read_string(name_addr['sh_offset'] + f['sh_name']) for f in section_data)

        self.sections = section_list(elf_section(self, sd, sn, i)
                                     for i, (sd, sn) in enumerate(zip(section_data, section_names)))

        ret_sections = [sh for sh in self.sections if sh.type == 'SHT_SYMTAB']
        self.symbol_table = ret_sections[0] if ret_sections else None

        ret_sections = [sh for sh in self.sections if sh.name == '.strtab']
        self.string_table = ret_sections[0] if ret_sections else None

        self.symbols = symbol_list(self._list_symbols())

        self.functions = symbol_list(s for s in self.symbols if s.info == 'STT_FUNC')
        self.objects = symbol_list(s for s in self.symbols if s.info == 'STT_OBJECT')

        self.code_relocations = self.get_relocations('.rela.text')

    def _list_sections(self):
        for i in range(self.fields['e_shnum']):
            offs = self.fields['e_shoff'] + i * self.fields['e_shentsize']
            yield {fn: self._read_from_sh_field(offs, fn) for fn in fdat.section_header.keys()}

    def _list_symbols(self):
        if self.symbol_table:
            offs = self.symbol_table['sh_offset']
            
            for j, i in enumerate(range(offs, self.symbol_table['sh_size']+offs, self.symbol_table['sh_entsize'])):
                ret = {'st_name': self.read_int(i, 4)}
                
                if self.bit_width == 32:
                    ret['st_value'] = self.read_int(i+4, 4)
                    ret['st_size'] = self.read_int(i+8, 4)
                    ret['st_info'] = self.read_int(i+12, 1)
                    ret['st_other'] = self.read_int(i+13, 1)
                    ret['st_shndx'] = self.read_int(i+14, 2)
                elif self.bit_width == 64:
                    ret['st_info'] = self.read_int(i+4, 1)
                    ret['st_other'] = self.read_int(i+5, 1)
                    ret['st_shndx'] = self.read_int(i+6, 2)
                    ret['st_value'] = self.read_int(i+8, 8)
                    ret['st_size'] = self.read_int(i+16, 8)
                    
                yield elf_symbol(self, ret, j)

    def get_relocations(self, reloc_section: elf_section | str | None = None) -> relocation_list:
        if isinstance(reloc_section, elf_section):
            assert reloc_section.type == 'SHT_RELA', f'{reloc_section.name} is not a relocation section'
            return relocation_list(self._list_relocations(reloc_section))
        else:
            relocations: list[elf_relocation] = list()
            for sh in self.sections:
                if sh.type == 'SHT_RELA':
                    if sh.name == reloc_section or not isinstance(reloc_section, str):
                        relocations += relocation_list(self._list_relocations(sh))
                        
            return relocation_list(relocations)

    def _list_relocations(self, sh: elf_section):
        assert sh.type == 'SHT_RELA', \
        'Section must be a relocation section (currently only SHT_RELA is supported)'

        offs = sh['sh_offset']
        for i in range(offs, sh['sh_size']+offs, sh['sh_entsize']):
            ret: dict[str, int] = dict()
        
            if self.bit_width == 32:
                ret['r_offset'] = self.read_int(i, 4)
                r_info = self.read_int(i+4, 4)
                ret['r_info'] = r_info
                ret['r_addend'] = self.read_int(i+8, 4, True)
                yield elf_relocation(self, ret, r_info >> 8, r_info & 0xFF, sh['sh_info'])
            elif self.bit_width == 64:
                ret['r_offset'] = self.read_int(i, 8)
                r_info = self.read_int(i+8, 8)
                ret['r_info'] = r_info
                ret['r_addend'] = self.read_int(i+16, 8, True)
                yield elf_relocation(self, ret, r_info >> 32, r_info & 0xFFFFFFFF, sh['sh_info'])
    
    def read_bytes(self, offset: int, num_bytes: int):
        return self._data[offset:offset + num_bytes]

    def read_int(self, offset: int, num_bytes: int, signed: bool = False) -> int:
        return int.from_bytes(self._data[offset:offset+num_bytes], self.byteorder, signed=signed)

    # def int_to_bytes(self, value: int, num_bytes: int = 4, signed: bool = False) -> int:
    #     return value.to_bytes(length=num_bytes, byteorder=self.byteorder, signed=signed)
    
    def read_string(self, offset: int) -> str:
        str_end = self._data.find(b'\x00', offset)
        return self._data[offset:str_end].decode()
    
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
    