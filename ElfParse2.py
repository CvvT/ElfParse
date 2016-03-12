__author__ = 'CwT'
import struct
import Util
import OatParse

class Symbol:
    def __init__(self):
        self.str = None     # name
        self.name = 0       # index of name
        self.value = 0
        self.size = 0
        self.info = 0
        self.other = 0
        self.shndx = 0
        self.size = 4 * 3 + 2 * 1 + 2

    def readfromfd(self, file):
        value = struct.unpack("IIIBBH", file.read(self.size))
        self.name = value[0]
        self.value = value[1]
        self.size = value[2]
        self.info = value[3]
        self.other = value[4]
        self.shndx = value[5]

    def dump(self):
        print "index(or name):", self.name if not self.str else self.str
        print "value:", hex(self.value)
        print "size:", hex(self.size)
        print "info:", hex(self.info)
        print "other:", hex(self.other)
        print "section head index:", self.shndx

class Shdr:
    TYPE = {
        0: 'SHT_NULL',  # No associated section
        1: 'SHT_PROGBITS',  # Program-defined contents
        2: 'SHT_SYMTAB',    # Symbol table
        3: 'SHT_STRTAB',    # String table
        4: 'SHT_RELA',  # Relocation entries; explicit addends
        5: 'SHT_HASH',  # Symbol hash table
        6: 'SHT_DYNAMIC',   # Information for dynamic linking
        7: 'SHT_NOTE',  # Information about the file
        8: 'SHT_NOBITS',    # Data occupies no space in the file
        9: 'SHT_REL',   # Relocation entries; no explicit addends
        10: 'SHT_SHLIB',    # Reserved
        11: 'SHT_DYNSYM',   # Symbol table
        14: 'SHI_INIT_ARRAY',   # Pointers to initialization functions
        15: 'SHT_FINT_ARRAY',   # Pointers to termination functions
        16: 'SHT_PREINIT_ARRAY',    # Pointers to pre-init functions
        17: 'SHT_GROUP',    # Section group
        18: 'SHT_SYMTAB_SHNDX',     # indices for SHN_XINDEX entries
        0x60000000: 'SHT_LOOS',     # Lowest operating system-specific type
        0x6ffffff5: 'SHT_GNU_ATTRIBUTES',   # object attributes
        0x6fffffd6: 'SHT_GNU_HASH',  # GNU-style hash table
        0x6ffffffd: 'SHT_GNU_verdef',  # GNU version definitions
        0x6ffffffe: 'SHT_GNU_verneed',  # GNU version references
        0x6fffffff: 'SHT_GNU_versym',   # GNU symbol versions table

        0x70000001: 'SHT_ARM_EXIDX',    # Exception index table
        0x70000002: 'SHT_ARM_PREEMPTMAP',   # BPABI DLL dynamic linking pre-emption map
        0x70000003: 'SHT_ARM_ATTRIBUTES',   # Object file compatibility attributes
        0x70000004: 'SHT_ARM_DEBUGOVERLAY',
        0x70000005: 'SHT_ARM_OVERLAYSECTIOn',
        0x70000006: 'SHT_HEX_ORDERED',
    }

    SHF_WRITE = 1
    SHF_ALLOC = 2
    SHF_EXECINSTR = 0x4
    SHF_MERGE = 0x10
    SHF_STRINGS = 0x20
    SHF_INFO_LINK = 0x40
    SHF_LINK_ORDER = 0x80
    SHF_OS_NONCONFORMING = 0x100
    SHF_GROUP = 0x200
    SHF_TLS = 0x400
    SHF_EXCLUDE = 0x80000000

    def __init__(self):
        self.str = None
        self.name = 0   # index of section header string table section
        self.type = 0
        self.flags = 0
        self.addr = 0   # address in memory
        self.offset = 0     # offset from the beginning of the file
        self.size = 0
        self.link = 0   # depend on its type
        self.info = 0
        self.addralign = 0
        self.entsize = 0    # size of records contained within this section
        self.size = 40

    def setName(self, str):
        self.str = str

    def readfromfd(self, file):
        value = struct.unpack("IIIIIIIIII", file.read(self.size))
        self.name = value[0]
        self.type = value[1]
        self.flags = value[2]
        self.addr = value[3]
        self.offset = value[4]
        self.size = value[5]
        self.link = value[6]
        self.info = value[7]
        self.addralign = value[8]
        self.entsize = value[9]

    def dump(self):
        print "Name index(or name):", self.name if not self.str else self.str
        print "type:", hex(self.type) if self.type not in Shdr.TYPE.keys() else Shdr.TYPE[self.type]
        print "flag:", hex(self.flags)
        print "address in memory", hex(self.addr)
        print "address in file", hex(self.offset)
        print "size in memory", hex(self.size)
        print "table link:", self.link
        print "section info:", self.info
        print "address alignment:", hex(self.addralign)
        print "size of records:", self.entsize


class Phdr:
    TYPE = {0: 'PT_NULL',   # unused
            1: 'PT_LOAD',   # loadable segment
            2: 'PT_DYNAMIC',    # dynamic link information
            3: 'PT_INTERP',     # interpreter pathname
            4: 'PT_NOTE',   # Auxiliary information
            5: 'PT_SHLIB',  # Reserved
            6: 'PT_PHDR',   # The program header table itself
            7: 'PT_TLS',    # The thread pool storage template
            0x60000000: 'PT_LOOS',  # Lowest operating system-specific pt entry
            0x6fffffff: 'PT_HIOS',  # Highest operation system-specific pt entry
            # 'PT_LOPROC': 0x70000000,  # Lowest processor-specific program hdr entry
            0x7fffffff: 'PT_HIPROC',    # Highest ...

            # x86-64 program header types
            0x6474e550: 'PT_GNU_EH_FRAME',
            0x6474e551: 'PT_GNU_STACK',     # indicate stack executability
            0x6474e552: 'PT_GNU_RELRO',     # Read-only after relocation

            # ARM program header types
            0x70000000: 'PT_ARM_ARCHEXT',   # platform architecture compatibility info
            # These all contain stack unwind tables
            0x70000001: 'PT_ARM_EXIDX',     # same as PT_ARM_UNWIND
            }

    PF_X = 1    # execute
    PF_W = 2    # write
    PF_R = 4    # read

    def isReadable(self):
        return self.flags & Phdr.PF_R != 0

    def isWritable(self):
        return self.flags & Phdr.PF_W != 0

    def isExecutable(self):
        return self.flags & Phdr.PF_X != 0

    def __init__(self):
        self.type = 0
        self.offset = 0
        self.vaddr = 0     # virtual address
        self.paddr = 0      # physical address
        self.filesz = 0     # size in file
        self.memsz = 0      # size in memory
        self.flags = 0
        self.align = 0
        self.size = 32

    def readfromfd(self, file):
        value = struct.unpack("IIIIIIII", file.read(self.size))
        self.type = value[0]
        self.offset = value[1]
        self.vaddr = value[2]
        self.paddr = value[3]
        self.filesz = value[4]
        self.memsz = value[5]
        self.flags = value[6]
        self.align = value[7]

    def dump(self):
        print "Type:", Phdr.TYPE[self.type]
        print "offset:", hex(self.offset)
        print "virtual address:", hex(self.vaddr)
        print "physical address:", hex(self.paddr)
        print "size in file:", hex(self.filesz)
        print "size in memory:", hex(self.memsz)
        print "Flags:", "PF_R" if self.isReadable() else '', "PF_W" if self.isWritable() else '', "PF_E" if self.isExecutable() else ''
        print "Alignment:", hex(self.align)

class Ehdr:
    def __init__(self):
        self.ident = []  # 16 bytes
        self.type = 0    # 0: unknown; 1: relocation 2: execute 3: share
        self.machine = 0
        self.version = 0    # version: 1
        self.entry = 0
        self.phoff = 0  # program header table offset
        self.shoff = 0  # section header table offset
        self.flags = 0
        self.ehsize = 0     # size of elf header
        self.phentsize = 0  # size of each program table entry
        self.phnum = 0      # number of program table entries
        self.shentsize = 0  # size of each section table entry
        self.shnum = 0      # number of section table entries
        self.shstrndx = 0   # section header string index
        self.size = 52  # total bytes

    def readfd(self, file):
        file.seek(0)
        value = struct.unpack("16sHHIIIIIHHHHHH", file.read(self.size))
        self.ident = value[0]
        self.type = value[1]
        self.machine = value[2]
        self.version = value[3]
        self.entry = value[4]
        self.phoff = value[5]
        self.shoff = value[6]
        self.flags = value[7]
        self.ehsize = value[8]
        self.phentsize = value[9]
        self.phnum = value[10]
        self.shentsize = value[11]
        self.shnum = value[12]
        self.shstrndx = value[13]

    def dump(self):
        print "ident:",
        for x in self.ident:
            print hex(ord(x)),
        print ''
        print "type:", self.type
        print "machine:", self.machine
        print "version:", self.version
        print "entry Addr:", hex(self.entry)
        print "program header table offset:", hex(self.phoff)
        print "section header table offset:", hex(self.shoff)
        print "flag", hex(self.flags)
        print "size of ELF header:", self.ehsize
        print "size of program header:", self.phentsize
        print "number of program header:", self.phnum
        print "size of section header:", self.shentsize
        print "number of section header:", self.shnum
        print "index of string table section:", self.shstrndx

class ELFile:
    def __init__(self):
        self.ehdr = Ehdr()
        self.shTab = None
        self.symTab = None

    def readfd(self, file):
        self.ehdr.readfd(file)

    def getShTab(self, file):
        if self.shTab is not None:
            return self.shTab
        file.seek(self.ehdr.shoff)
        shtab = []
        for i in range(self.ehdr.shnum):
            shdr = Shdr()
            shdr.readfromfd(file)
            shtab.append(shdr)
        strtab = shtab[self.ehdr.shstrndx]
        for i in range(self.ehdr.shnum):
            shtab[i].setName(Util.getStrbyfd(file, shtab[i].name + strtab.offset))
        self.shTab = shtab
        return shtab

    def getSymTab(self, file):
        if self.symTab is not None:
            return self.symTab
        shtab = self.getShTab(file)
        symtab = []
        symStr = None
        for shdr in shtab:
            if shdr.str == '.dynsym':     # DYNSYM
                file.seek(shdr.offset)
                for i in range(shdr.size / 16):
                    sym = Symbol()
                    sym.readfromfd(file)
                    symtab.append(sym)
            elif shdr.str == '.dynstr':
                symStr = shdr
        if symStr is not None:
            for sym in symtab:
                sym.str = Util.getStrbyfd(file, sym.name + symStr.offset)
        self.symTab = symtab
        return symtab

    def dump(self):
        self.ehdr.dump()

    def dumpPhdr(self, file):
        file.seek(self.ehdr.phoff)
        for i in range(self.ehdr.phnum):
            phdr = Phdr()
            phdr.readfromfd(file)
            phdr.dump()
            print ''

    def dumpShdr(self, file):
        shtab = self.getShTab(file)
        for i in range(self.ehdr.shnum):
            shtab[i].dump()
            print ''

    def dumpSymTab(self, file):
        symtab = self.getSymTab(file)
        for sym in symtab:
            sym.dump()
            print ''

if __name__ == '__main__':
    elf = ELFile()
    with open("test/c", "rb") as file:
        elf.readfd(file)
        elf.dumpShdr(file)
        shtab = elf.getShTab(file)
        for shdr in shtab:
            if shdr.str == ".rodata":
                oatFile = OatParse.OATfile()
                oatFile.readfd(file, shdr.offset)
                for dex in oatFile.getDexFiles(file):
                    print dex.name
