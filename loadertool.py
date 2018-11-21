#!/usr/bin/python3
#Author:        Jacob Mills
#Date           11/20/2018
#Description:   Python module providing a LoaderTool class that can be used as a utility for
#               loading binaries of various object formats, including ELF and PE.
#

import struct

class LoaderTool(object):
    """
    Class serving as a base object loader
    """

    def check_elf_magic(self, filename):
        elfmagic =  [0x7f,0x45,0x4c,0x46]
        with open(filename,'rb') as binary:
            data = binary.read(4)
            for i in range(0,4):
                if elfmagic[i] != data[i]:
                    return False
        return True

    def check_pe_magic(self, filename):
        pemagic = [0x4d, 0x5a]
        with open(filename,'rb') as binary:
            data = binary.read(2)
            for i in range(0,2):
                if pemagic[i] != data[i]:
                    return False
        return True


    def __init__(self, filename):
        self.isELF = self.check_elf_magic(filename)
        self.isPE = self.check_pe_magic(filename)
        if not self.isELF and not self.isPE:
            print("ERROR: {} is not a supported format (ELF,PE)".format(filename))
            return
        self.ELF = None
        self.PE = None

        if self.isELF:
            print("ELF detected")
            self.ELF = ELFClass(filename)
            self.ELF.debug()
        elif self.isPE:
            print("PE detected")
            self.PE = PEClass(filename)


class ELFClass(object):
    """
    Class serving as an ELF object parser
    """
    def __init__(self,filename):
        with open(filename,'rb') as binary:
            self._magic = binary.read(4)
            self._class = ord(binary.read(1)) #1 = 32 bit, 2 = 64 bit
            self._byteorder = ord(binary.read(1)) #1 = little, 2 = big

            # now create endianness char e to represent little or big endianness for unpacking
            e = '<' if self._byteorder == 1 else '>'

            self._hversion = ord(binary.read(1))
            self._osabi = ord(binary.read(1))
            self._abiversion = ord(binary.read(1))
            self._pad = binary.read(7)
            self._filetype = struct.unpack(e+'H', binary.read(2))[0]
            self._archtype = struct.unpack(e+'H', binary.read(2))[0]
            self._fversion = struct.unpack(e+'I', binary.read(4))[0]

            if self._class == 1:
                self._entry = struct.unpack(e+'I', binary.read(4))[0]
                self._phdrpos = struct.unpack(e+'I', binary.read(4))[0]
                self._shdrpos = struct.unpack(e+'I', binary.read(4))[0]
            else:
                self._entry = struct.unpack(e+'Q', binary.read(8))[0]
                self._phdrpos = struct.unpack(e+'Q', binary.read(8))[0]
                self._shdrpos = struct.unpack(e+'Q', binary.read(8))[0]

            self._flags = struct.unpack(e+'I', binary.read(4))[0]
            self._hdrsize = struct.unpack(e+'H', binary.read(2))[0]
            self._phdrent = struct.unpack(e+'H', binary.read(2))[0]
            self._phdrcnt = struct.unpack(e+'H', binary.read(2))[0]
            self._shdrent = struct.unpack(e+'H', binary.read(2))[0]
            self._shdrcnt = struct.unpack(e+'H', binary.read(2))[0]
            self._strsec = struct.unpack(e+'H', binary.read(2))[0]


    def debug(self):
        print("""
Magic:\t\t\t{}
Class:\t\t\t{}
Byteorder:\t\t{}
HeaderVersion:\t\t{}
OSABI:\t\t\t{}
ABIversion:\t\t{}
filetype:\t\t{}
archtype:\t\t{}
FileVersion:\t\t{}
Entry:\t\t\t{}
ProgramHeader:\t\t{}
SectionHeader:\t\t{}
Flags:\t\t\t{}
HeaderSize:\t\t{}
ProgramHeaderEntrySize:\t{}
ProgramHeaderEntries:\t{}
SectionHeaderEntrySize:\t{}
SectionHeaderEntries:\t{}
StringSectionIndex:\t{}
        """.format(
            self._magic,
            "32 bit" if self._class == 1 else "64 bit",
            "little endian" if self._byteorder == 1 else "big endian",
            self._hversion,
            self.get_os_abi(),
            self._abiversion,
            self.get_filetype(),
            self.get_archtype(),
            self._fversion,
            hex(self._entry),
            hex(self._phdrpos),
            hex(self._shdrpos),
            hex(self._flags),
            hex(self._hdrsize),
            hex(self._phdrent),
            hex(self._phdrcnt),
            hex(self._shdrent),
            hex(self._shdrcnt),
            hex(self._strsec)
            ))

    def get_os_abi(self):
        switch = {
            0x0:'System V',
            0x1:'HP-UX',
            0x2:'NetBSD',
            0x3:'Linux',
            0x4:'GNU Hurd',
            0x6:'Solaris',
            0x7:'AIX',
            0x8:'IRIX',
            0x9:'FreeBSD',
            0xA:'Tru64',
            0xB:'Novell Modesto',
            0xC:'OpenBSD',
            0xD:'OpenVMS',
            0xE:'NonStop Kernel',
            0xF:'AROS',
            0x10:'Fenix OS',
            0x11:'CloudABI'
            }
        return switch[self._osabi]

    def get_filetype(self):
        switch = {
            0x0000:'ET_NONE',
            0x0001:'ET_REL',
            0x0002:'ET_EXEC',
            0x0003:'ET_DYN',
            0x0004:'ET_CORE',
            0xFE00:'ET_LOOS',
            0xFEFF:'ET_HOIS',
            0xFF00:'ET_LOPROC',
            0xFFFF:'ET_HIPROC'
            }
        return switch[self._filetype]

    def get_archtype(self):
        switch = {
            0x00:'n/a',
            0x02:'SPARC',
            0x03:'x86',
            0x08:'MIPS',
            0x14:'PowerPC',
            0x16:'S390',
            0x28:'ARM',
            0x2A:'SuperH',
            0x32:'IA-64',
            0x3E:'x86-64',
            0xB7:'AArch64',
            0xF3:'RISC-V'
            }
        return switch[self._archtype]

class PEClass(object):
    def __init__(self,filename):
        pass
