__author__ = 'CwT'
import struct

def elf_hash(funcname):
    h = 0
    for x in funcname:
        h = (h << 4) + ord(x)
        g = h & 0xf0000000
        h ^= g
        h ^= g >> 24
    print()
    return h

class Ehdr:
    def __init__(self):
        self.ident = []
        self.type = 0   # 0: unknow; 1: relocation 2: execute 3: share
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
        self.size = 52  # bytes
        self.shtable = None
        self.phtable = None
        self.dyntable = None

    def readfromfd(self, file):
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

    def init_table(self):
        self.shtable = ShTable()
        self.shtable.readfromfd(file, self.shoff, self.shnum, self.shstrndx)
        self.phtable = PhTable()
        self.phtable.readfromfd(file, self.phoff, self.phnum)
        tmp = self.phtable.getSegment("PT_DYNAMIC")
        self.dyntable = DynTable(tmp.offset, tmp.filesz)
        self.dyntable.readfromfd(file)

    def printf(self):
        for x in self.ident:
            print hex(ord(x)),
        print ''
        print(self.type)
        print(self.machine)
        print(self.version)
        print(self.entry)
        print(self.phoff)
        print(self.shoff)
        print(self.flags)
        print(self.ehsize)
        print(self.phentsize)
        print(self.phnum)
        print(self.shentsize)
        print(self.shnum)
        print(self.shstrndx)

class Shder:
    def __init__(self):
        self.name = 0   # index of section header string table section
        self.type = 0
        self.flags = 0
        self.addr = 0
        self.offset = 0     # offset from the beginning of the file
        self.size = 0
        self.link = 0
        self.info = 0
        self.addralign = 0
        self.entsize = 0
        self.size = 40

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

class ShTable:
    def __init__(self):
        self.shtable = []
        self.off = 0
        self.num = 0
        self.shstrtable = []
        self.strtab = []
        self.symtab = []
        self.hashtable = None

    def getstrtablefromfd(self, file, str_index):
        sh = self.shtable[str_index]
        file.seek(sh.offset)
        for i in range(0, sh.size):
            self.shstrtable.append(struct.unpack("c", file.read(1))[0])

    def readfromfd(self, file, shoff, shnum, str_index):
        file.seek(shoff)
        self.off = shoff
        self.num = shnum
        for i in range(0, shnum):
            shder = Shder()
            shder.readfromfd(file)
            self.shtable.append(shder)
        self.getstrtablefromfd(file, str_index)
        self.getSymstr(file)
        self.getSymtab(file)
        self.gethash(file)

    def getshname(self, index):
        start = index
        while 1:
            if self.shstrtable[index] == '\0':
                break
            index += 1
        return "".join(self.shstrtable[start:index])

    def findsection(self, secName):
        for i in range(0, self.num):
            if self.getshname(self.shtable[i].name) == secName:
                return self.shtable[i]
        return None

    def getSymstr(self, file):
        tmp = self.findsection(".dynstr")
        if tmp is not None:
            file.seek(tmp.offset)
            for i in range(0, tmp.size):
                self.strtab.append(struct.unpack("c", file.read(1))[0])
        else:
            print("error in getSymstr")

    def getSymtab(self, file):
        tmp = self.findsection(".dynsym")
        if tmp is not None:
            len = tmp.size / tmp.entsize
            file.seek(tmp.offset)
            for i in range(0, len):
                sym = Symbol()
                sym.readfromfd(file)
                self.symtab.append(sym)
        else:
            print("error in get symtab")

    def gethash(self, file):
        tmp = self.findsection(".hash")
        if tmp is not None:
            self.hashtable = Hash()
            self.hashtable.readfromfd(file, tmp.offset)
        else:
            print("error in gethash")

    def getnamebyindex(self, index):
        start = index
        while 1:
            if self.strtab[index] == '\0':
                break
            index += 1
        return "".join(self.strtab[start:index])

    def getfuncinfo(self, funcname):
        index = elf_hash(funcname) % self.hashtable.nbucket
        index = self.hashtable.getbucket(index)
        if index >= len(self.symtab):
            print("error, get symbol table first")
            exit()
        str_index = self.symtab[index].name
        if self.getnamebyindex(str_index) != funcname:
            while 1:
                index = self.hashtable.getchain(index)
                if index == 0:
                    print("did not find the func %s" %funcname)
                    break
                str_index = self.symtab[index].name
                if self.getnamebyindex(str_index) == funcname:
                    break
        if index == 0:
            return None
        return self.symtab[index]

    def printf(self):
        for i in range(0, self.num):
            print(self.getshname(self.shtable[i].name))

    def printsym(self):
        for i in range(0, len(self.symtab)):
            print(self.getnamebyindex(self.symtab[i].name))

class Phdr:
    TYPE = {'PT_NULL': 0, 'PT_LOAD': 1, 'PT_DYNAMIC': 2, 'PT_INTERP': 3,
            'PT_NOTE': 4, 'PT_SHLIB': 5, 'PT_PHDR': 6, }

    def __init__(self):
        self.type = 0
        self.offset = 0
        self.vaddr = 0     # virtual address
        self.paddr = 0      # physical address
        self.filesz = 0     # size in file
        self.memsz = 0      # size in memory
        self.flags = 0
        self.align = 0
        self.size = 8 * 4

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

class PhTable:
    def __init__(self):
        self.phtable = []
        self.num = 0
        self.off = 0

    def readfromfd(self, file, offset, phnum):
        file.seek(offset)
        self.off = offset
        self.num = phnum
        for i in range(0, self.num):
            phdr = Phdr()
            phdr.readfromfd(file)
            self.phtable.append(phdr)

    def getSegment(self, segName):
        if segName not in Phdr.TYPE.keys():
            print("unknow segment name")
            return None
        for i in range(0, self.num):
            if self.phtable[i].type == Phdr.TYPE[segName]:
                print("find %s" % (segName))
                return self.phtable[i]

class Symbol:
    def __init__(self):
        self.name = 0
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

class Dynamic:
    TAG = {0: 'DT_NULL', 1: 'DT_NEEDED', 2: 'DT_PLTRELSZ', 3: 'DT_PLTGOT',
           4: 'DT_HASH', 5: 'DT_STRTAB', 6: 'DT_SYMTAB', 7: 'DT_RELA',
           8: 'DT_REALSZ', 9: 'DT_RELAENT', 10: 'DT_STRSZ', 11: 'DT_SYMENT',
           12: 'DT_INIT', 13: 'DT_FINI', 14: 'DT_SONAME', 15: 'DT_RPATH',
           16: 'DT_SYMBOLIC', 17:'DT_REL', 18: 'DT_RELSZ', 19: 'DT_RELENT', 20: 'DT_PLTREL',
           21: 'DT_DEBUG', 22: 'DT_TEXTREL', 23: 'DT_JMPREL',
           25: 'DT_INIT_ARRAY', 26: 'DT_FINI_ARRAY', 27: 'DT_INIT_ARRAYSZ', 28: 'DT_FINI_ARRAYSZ',
           }

    def __init__(self):
        self.tag = 0
        self.union = 0
        self.size = 8

    def readfromfd(self, file):
        value = struct.unpack("iI", file.read(self.size))
        self.tag = value[0]
        self.union = value[1]

    def printf(self):
        if self.tag in Dynamic.TAG.keys():
            print("tag is: ", Dynamic.TAG[self.tag])
        else:
            print("tag is: ", self.tag)
        print("union is: ", self.union)
        print("size is: ", self.size)

class DynTable:
    TAG = {'DT_NULL': 0, 'DT_NEEDED': 1, 'DT_PLTRELSZ': 2, 'DT_PLTGOT': 3,
           'DT_HASH': 4, 'DT_STRTAB': 5, 'DT_SYMTAB': 6, 'DT_RELA': 7,
           'DT_REALSZ': 8, 'DT_RELAENT': 9, 'DT_STRSZ': 10, 'DT_SYMENT': 11,
           'DT_INIT': 12, 'DT_FINI': 13, 'DT_SONAME': 14, 'DT_RPATH': 15,
           'DT_SYMBOLIC': 16, 'DT_REL': 17, 'DT_RELSZ': 18, 'DT_RELENT': 19, 'DT_PLTREL': 20,
           'DT_DEBUG': 21, 'DT_TEXTREL': 22, 'DT_JMPREL': 23,
           'DT_INIT_ARRAY': 25, 'DT_FINI_ARRAY': 26, 'DT_INIT_ARRAYSZ': 27, ' DT_FINI_ARRAYSZ': 28, }

    def __init__(self, offset, size):
        self.off = offset
        self.size = size
        self.num = size / 8
        self.dyn = []
        self.strtab = []
        self.symtab_off = 0
        self.symtab = []
        self.hashtable = None

    def readfromfd(self, file):
        file.seek(self.off)
        for i in range(0, self.num):
            dyn = Dynamic()
            dyn.readfromfd(file)
            self.dyn.append(dyn)
        self.getStrtable(file)
        self.getHashtable(file)
        self.symtab_off = self.getsecBytag("DT_SYMTAB").union
        # self.getSymboltable(file)

    def getsecBytag(self, tag):
        for i in range(0, self.num):
            if self.dyn[i].tag == DynTable.TAG[tag]:
                return self.dyn[i]
        print("did not find %s" % tag)
        return None

    def getStrtable(self, file):
        offset = self.getsecBytag("DT_STRTAB").union
        size = self.getsecBytag("DT_STRSZ").union
        file.seek(offset)
        for i in range(0, size):
            self.strtab.append(struct.unpack("c", file.read(1))[0])

    def getHashtable(self, file):
        offset = self.getsecBytag("DT_HASH").union
        self.hashtable = Hash()
        self.hashtable.readfromfd(file, offset)

    def getSymboltable(self, file, filesz):
        offset = self.getsecBytag("DT_SYMTAB").union
        num = filesz / self.getsecBytag("DT_SYMENT").union   # size of each symbol entry
        file.seek(offset)
        for i in range(0, num):
            symbol = Symbol()
            symbol.readfromfd(file)
            self.symtab.append(symbol)

    def getnamebyindex(self, index):
        start = index
        while 1:
            if self.strtab[index] == '\0':
                break
            index += 1
        return "".join(self.strtab[start:index])

    def getfuncinfo(self, funcname, file):
        index = elf_hash(funcname) % self.hashtable.nbucket
        index = self.hashtable.getbucket(index)
        file.seek(self.symtab_off + index * 16)
        # str_index = self.symtab[index].name
        str_index = struct.unpack("I", file.read(4))[0]
        if self.getnamebyindex(str_index) != funcname:
            while 1:
                index = self.hashtable.getchain(index)
                print(index, "index")
                if index == 0:
                    print("did not find the func %s" %funcname)
                    break
                file.seek(self.symtab_off + index * 16)
                str_index = struct.unpack("I", file.read(4))[0]
                if self.getnamebyindex(str_index) == funcname:
                    break
        if index == 0:
            return None
        func = Symbol()
        file.seek(self.symtab_off + index * 16)
        func.readfromfd(file)
        return func

    def printSymbol(self):
        for i in range(0, len(self.symtab)):
            print(self.getnamebyindex(self.symtab[i].name))

class Hash:
    def __init__(self):
        self.nbucket = 0
        self.nchain = 0
        self.bucket = []
        self.chain = []

    def readfromfd(self, file, offset):
        file.seek(offset)
        value = struct.unpack("II", file.read(8))
        self.nbucket = value[0]
        self.nchain = value[1]
        for i in range(0, self.nbucket):
            self.bucket.append(struct.unpack("I", file.read(4))[0])
        for i in range(0, self.nchain):
            self.chain.append(struct.unpack("I", file.read(4))[0])

    def getbucket(self, index):
        if index >= self.nbucket:
            print("index %d out of range %d" % (index, self.nbucket))
            return -1
        return self.bucket[index]

    def getchain(self, index):
        return self.chain[index]

if __name__ == '__main__':
    file = open("libtest.so", "rb")
    elfheader = Ehdr()
    elfheader.readfromfd(file)
    elfheader.printf()
    file.close()
