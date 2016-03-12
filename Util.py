__author__ = 'CwT'
import struct

def getStrbyfd(file, addr):
    file.seek(addr)
    # print hex(addr)
    str = []
    byte = struct.unpack("B", file.read(1))[0]
    while byte:
        str.append(chr(byte))
        byte = struct.unpack("B", file.read(1))[0]
    return ''.join(str)
