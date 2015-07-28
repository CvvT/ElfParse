__author__ = 'CwT'

from ElfParse import *

if __name__ == '__main__':
    file = open("libbaiduprotect.so", 'r+b')
    file.seek(0)
    elfheader = Ehdr()
    elfheader.readfromfd(file)
    elfheader.init_table()
    addr = elfheader.shtable.findsection(".text").offset
    if addr == -1:
        print("find section .text failed")
        exit(0)
    # symbol = elfheader.shtable.getfuncinfo("native_hello")
    # symbol = elfheader.dyntable.getfuncinfo("native_hello", file)
    # print("func addr :", symbol.value - 1)  # i don't know why must minus one, it's the beginning of the text
    # file.seek(symbol.value - 1)
    # size = symbol.size
    # content = []
    # for i in range(0, size-1):
    #     content.append(~struct.unpack("B", file.read(1))[0] & 0xff)
    # file.seek(symbol.value - 1)
    # # print(struct.unpack("B", file.read(1))[0])
    # for i in range(0, size-1):
    #     # print(struct.pack("B", content[i]), )
    #     file.write(struct.pack("B", content[i]))
    # elfheader.shtable.printsym()
    elfheader.printf()
    file.close()
