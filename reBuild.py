__author__ = 'CwT'
from ElfParse import *

if __name__ == '__main__':
    file = open("libbaiduprotect.so", 'r+b')
    file.seek(0)
    elfheader = Ehdr()
    elfheader.readfromfd(file)
    phtable = PhTable()
    phtable.readfromfd(file, elfheader.phoff, elfheader.phnum)
    tmp = phtable.getSegment("PT_DYNAMIC")
    dyntable = DynTable(tmp.offset, tmp.filesz)
    dyntable.readfromfd(file)
    for i in range(0, dyntable.num):
        dyntable.dyn[i].printf()
    file.close()
