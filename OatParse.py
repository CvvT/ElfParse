__author__ = 'CwT'
import struct
import Util

class OATHdr:
    def __init__(self):
        self.offset = 0
        self.magic = []
        self.version = []
        self.checksum = 0
        self.dexfileCount = 0
        self.size = 0
        self.keyvalueSize = 0

    def readfd(self, file, offset):
        self.offset = offset
        file.seek(offset)
        value = struct.unpack("4s4sIIIIIIIIIIIIIIIIIII", file.read(21*4))
        self.magic = value[0]
        self.version = value[1]
        self.dexfileCount = value[5]
        self.keyvalueSize = value[20]

    def getHeaderSize(self):
        return self.keyvalueSize + 21 * 4

    def getDexListStart(self):
        return self.offset + self.getHeaderSize()

class DexMeta:
    def __init__(self):
        self.name = None
        self.dexOffset = 0
        self.classCount = 0

    def readfd(self, file, oatFile):
        filenameLen = struct.unpack("I", file.read(4))[0]
        self.name = struct.unpack(str(filenameLen)+"s", file.read(filenameLen))[0]
        value = struct.unpack("II", file.read(4*2))
        self.dexOffset = value[1]
        file.seek(oatFile.offset + self.dexOffset + 96)
        self.classCount = struct.unpack("I", file.read(4))[0]

    def getMetaSize(self):
        return 4 + len(self.name) + 4*2 + 4*self.classCount


class OATfile:
    def __init__(self):
        self.offset = 0
        self.oatHdr = OATHdr()

    def readfd(self, file, offset):
        self.offset = offset
        self.oatHdr.readfd(file, offset)

    def getDexFiles(self, file):
        offset = self.oatHdr.getDexListStart()
        dexFiles = []
        for i in range(self.oatHdr.dexfileCount):
            file.seek(offset)
            dexMeta = DexMeta()
            dexMeta.readfd(file, self)
            offset += dexMeta.getMetaSize()
            dexFiles.append(dexMeta)
            # print hex(offset)
        return dexFiles
