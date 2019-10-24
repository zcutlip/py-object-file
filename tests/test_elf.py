from pyobjfile.elf import File as Elf
import os

DATA_PATH = os.path.join("tests", "data", "elf")
HELLO_X86_64 = os.path.join(DATA_PATH, "hello-elf-x86_64")


def setup_elf_generic(filename):
    elf = Elf(filename)
    return elf


def setup_elf_x86_64():
    elf = setup_elf_generic(HELLO_X86_64)
    return elf


def test_open_elf_x86_64():
    elf = setup_elf_x86_64()
    assert elf.is_valid()


def setup_sections_x86_64():
    elf = setup_elf_x86_64()
    sections = elf.get_section_headers()
    return sections


def setup_get_sect_num_x86_64(sect_num):
    return setup_sections_x86_64()[sect_num]


def test_get_sections_x86_64_01():
    sections = setup_sections_x86_64()
    assert 36 == len(sections)


def test_get_sections_x86_64_02():
    text_section = setup_get_sect_num_x86_64(14)
    assert '.text' == text_section.name


def test_get_sections_x86_64_03():
    plt_section = setup_get_sect_num_x86_64(12)
    print(plt_section.name)
    print(hex(plt_section.sh_offset))
    assert 0x3f0 == plt_section.sh_offset


def test_get_c_string_x86_64():
    # $ strings -t x -a hello-elf-x86_64 | grep Hello
    # 5d4 Hello world
    elf = setup_elf_x86_64()
    hello_world_offset = 0x5d4
    elf.data.seek(hello_world_offset)
    data = elf.data.get_c_string()
    assert "Hello world" == data
