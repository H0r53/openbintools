#!/usr/bin/python3

"""
#Author:        Jacob Mills
#Date           11/20/2018
#Description:   Python module providing a LoaderTool class that can be used as a utility for
#               loading binaries of various object formats, including ELF and PE.
#Usage:         import loadertool
#               hdr = loadertool.LoaderTool('path-to-binary')
"""

import struct
import datetime


class LoaderTool(object):
    """
    Class serving as a base object loader
    """
    def __init__(self, filename):
        """

        :param filename:
        """
        self.isELF = self.check_elf_magic(filename)
        self.isPE = self.check_pe_magic(filename)
        if not self.isELF and not self.isPE:
            print("ERROR: {} is not a supported format (ELF,PE)".format(filename))
            return
        self.ELF = None
        self.PE = None

        if self.isELF:
            self.ELF = ELFClass(filename)
        elif self.isPE:
            self.PE = PEClass(filename)

    @staticmethod
    def check_elf_magic(filename):
        """

        :param filename:
        :return:
        """
        elfmagic = [0x7f, 0x45, 0x4c, 0x46]
        with open(filename, 'rb') as binary:
            data = binary.read(4)
            for i in range(0, 4):
                if elfmagic[i] != data[i]:
                    return False
        return True

    @staticmethod
    def check_pe_magic(filename):
        """

        :param filename:
        :return:
        """
        pemagic = [0x4d, 0x5a]
        with open(filename, 'rb') as binary:
            data = binary.read(2)
            for i in range(0, 2):
                if pemagic[i] != data[i]:
                    return False
        return True


class ELFClass(object):
    """
    Class serving as an ELF object parser
    """
    def __init__(self, filename):
        """

        :param filename:
        """
        with open(filename, 'rb') as binary:
            self._magic = binary.read(4)
            self._class = ord(binary.read(1))  # 1 = 32 bit, 2 = 64 bit
            self._byteorder = ord(binary.read(1))  # 1 = little, 2 = big

            # now create endianness char e to represent little or big endianness for unpacking
            endianness = '<' if self._byteorder == 1 else '>'

            self._hversion = ord(binary.read(1))
            self._osabi = ord(binary.read(1))
            self._abiversion = ord(binary.read(1))
            self._pad = binary.read(7)
            self._filetype = struct.unpack(endianness+'H', binary.read(2))[0]
            self._archtype = struct.unpack(endianness+'H', binary.read(2))[0]
            self._fversion = struct.unpack(endianness+'I', binary.read(4))[0]

            if self._class == 1:
                self._entry = struct.unpack(endianness+'I', binary.read(4))[0]
                self._phdrpos = struct.unpack(endianness+'I', binary.read(4))[0]
                self._shdrpos = struct.unpack(endianness+'I', binary.read(4))[0]
            else:
                self._entry = struct.unpack(endianness+'Q', binary.read(8))[0]
                self._phdrpos = struct.unpack(endianness+'Q', binary.read(8))[0]
                self._shdrpos = struct.unpack(endianness+'Q', binary.read(8))[0]

            self._flags = struct.unpack(endianness+'I', binary.read(4))[0]
            self._hdrsize = struct.unpack(endianness+'H', binary.read(2))[0]
            self._phdrent = struct.unpack(endianness+'H', binary.read(2))[0]
            self._phdrcnt = struct.unpack(endianness+'H', binary.read(2))[0]
            self._shdrent = struct.unpack(endianness+'H', binary.read(2))[0]
            self._shdrcnt = struct.unpack(endianness+'H', binary.read(2))[0]
            self._strsec = struct.unpack(endianness+'H', binary.read(2))[0]

    def info(self):
        """

        :return:
        """
        information = """Magic:\t\t\t{}
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
            "ELF",
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
            )
        return information

    def get_os_abi(self):
        """

        :return:
        """
        switch = {
            0x0: 'System V',
            0x1: 'HP-UX',
            0x2: 'NetBSD',
            0x3: 'Linux',
            0x4: 'GNU Hurd',
            0x6: 'Solaris',
            0x7: 'AIX',
            0x8: 'IRIX',
            0x9: 'FreeBSD',
            0xA: 'Tru64',
            0xB: 'Novell Modesto',
            0xC: 'OpenBSD',
            0xD: 'OpenVMS',
            0xE: 'NonStop Kernel',
            0xF: 'AROS',
            0x10: 'Fenix OS',
            0x11: 'CloudABI'
            }
        return switch[self._osabi]

    def get_filetype(self):
        """

        :return:
        """
        switch = {
            0x0000: 'ET_NONE',
            0x0001: 'ET_REL',
            0x0002: 'ET_EXEC',
            0x0003: 'ET_DYN',
            0x0004: 'ET_CORE',
            0xFE00: 'ET_LOOS',
            0xFEFF: 'ET_HOIS',
            0xFF00: 'ET_LOPROC',
            0xFFFF: 'ET_HIPROC'
            }
        return switch[self._filetype]

    def get_archtype(self):
        """

        :return:
        """
        switch = {
            0x00: 'n/a',
            0x02: 'SPARC',
            0x03: 'x86',
            0x08: 'MIPS',
            0x14: 'PowerPC',
            0x16: 'S390',
            0x28: 'ARM',
            0x2A: 'SuperH',
            0x32: 'IA-64',
            0x3E: 'x86-64',
            0xB7: 'AArch64',
            0xF3: 'RISC-V'
            }
        return switch[self._archtype]


class PEClass(object):
    """
    Class serving as a PE object parser
    """
    def __init__(self, filename):
        """

        :param filename:
        """
        with open(filename, 'rb') as binary:
            self._mz_signature = binary.read(2)
            self._mz_lastsize = struct.unpack('<H', binary.read(2))[0]
            self._mz_nblocks = struct.unpack('<H', binary.read(2))[0]
            self._mz_nreloc = struct.unpack('<H', binary.read(2))[0]
            self._mz_hdrsize = struct.unpack('<H', binary.read(2))[0]
            self._mz_minalloc = struct.unpack('<H', binary.read(2))[0]
            self._mz_maxalloc = struct.unpack('<H', binary.read(2))[0]
            self._mz_initial_ss = struct.unpack('<H', binary.read(2))[0]
            self._mz_initial_sp = struct.unpack('<H', binary.read(2))[0]
            self._mz_checksum = struct.unpack('<H', binary.read(2))[0]
            self._mz_initial_ip = struct.unpack('<H', binary.read(2))[0]
            self._mz_initial_cs = struct.unpack('<H', binary.read(2))[0]
            self._mz_relocpos = struct.unpack('<H', binary.read(2))[0]
            self._mz_noverlay = struct.unpack('<H', binary.read(2))[0]
            self._mz_reserved1 = []
            for _ in range(0, 4):
                self._mz_reserved1.append(struct.unpack('<H', binary.read(2))[0])
            self._mz_oem_id = struct.unpack('<H', binary.read(2))[0]
            self._mz_oem_info = struct.unpack('<H', binary.read(2))[0]
            self._mz_reserved2 = []
            for _ in range(0, 10):
                self._mz_reserved2.append(struct.unpack('<H', binary.read(2))[0])
            self._mz_peoffset = struct.unpack('<I', binary.read(4))[0]

            binary.read(self._mz_peoffset - 0x40)  # Skip to PE offset

            self._pe_signature = binary.read(4)
            self._pe_machine = struct.unpack('<H', binary.read(2))[0]
            self._pe_numsections = struct.unpack('<H', binary.read(2))[0]
            self._pe_timedatestamp = struct.unpack('<I', binary.read(4))[0]
            self._pe_symtab_ptr = struct.unpack('<I', binary.read(4))[0]
            self._pe_symcnt = struct.unpack('<I', binary.read(4))[0]
            self._pe_opt_tab_size = struct.unpack('<H', binary.read(2))[0]
            self._pe_characteristics = struct.unpack('<H', binary.read(2))[0]

    def info(self):
        """

        :return:
        """
        information = """MZ Signature:\t\t{}
MZ LastPageExtraBytes:\t{}
MZ NPages:\t\t{}
MZ NRelocs:\t\t{}
MZ HeaderSize:\t\t{}
MZ MinAlloc:\t\t{}
MZ MaxAlloc:\t\t{}
MZ Initial SS:\t\t{}
MZ Initial SP:\t\t{}
MZ Checksum:\t\t{}
MZ Initial IP:\t\t{}
MZ Initial CS:\t\t{}
MZ RelocPosition:\t{}
MZ NOverlay:\t\t{}
MZ OEM ID:\t\t{}
MZ OEM INFO:\t\t{}
MZ PE offset:\t\t{}
PE Signature:\t\t{}
PE Machine:\t\t{}
PE NumSections:\t\t{}
PE TimeDateStamp:\t{}
PE Symbol Table:\t{}
PE Symbol Count:\t{}
PE Optional Table Size:\t{}
PE Characteristics:\t{}
        """.format(
            self._mz_signature.decode('utf-8'),
            self._mz_lastsize,
            self._mz_nblocks,
            self._mz_nreloc,
            self._mz_hdrsize,
            self._mz_minalloc,
            self._mz_maxalloc,
            hex(self._mz_initial_ss),
            hex(self._mz_initial_sp),
            hex(self._mz_checksum),
            hex(self._mz_initial_ip),
            hex(self._mz_initial_cs),
            hex(self._mz_relocpos),
            self._mz_noverlay,
            self._mz_oem_id,
            self._mz_oem_info,
            hex(self._mz_peoffset),
            self._pe_signature.decode('utf-8'),
            self.get_pe_machine(),
            self._pe_numsections,
            datetime.datetime.fromtimestamp(self._pe_timedatestamp),
            self._pe_symtab_ptr,
            self._pe_symcnt,
            self._pe_opt_tab_size,
            self.get_pe_chars()
            )
        return information

    def get_pe_machine(self):
        """

        :return:
        """
        switch = {
            0x00: 'any',
            0x1d3: 'Matsushita AM33',
            0x8664: 'x64',
            0x1c0: 'ARM little endian',
            0xaa64: 'ARM64 little endian',
            0x1c4: 'ARM Thumb-2 little endian',
            0xebc: 'EFI byte code',
            0x14c: 'Intel 386 or later',
            0x200: 'Intel Itanium processor family',
            0x9041: 'Mitsubishi M32R little endian',
            0x266: 'MIPS16',
            0x366: 'MIPS with FPU',
            0x466: 'MIPS16 with FPU',
            0x1f0: 'Power PC little endian',
            0x1f1: 'Power PC with floating point support',
            0x166: 'MIPS little endian',
            0x5032: 'RISC-V 32-bit address space',
            0x5064: 'RISC-V 64-bit address space',
            0x5128: 'RISC-V 128-bit address space',
            0x1a2: 'Hitachi SH3',
            0x1a3: 'Hitachi SH3 DSP',
            0x1a6: 'Hitachi SH4',
            0x1a8: 'Hitachi SH5',
            0x1c2: 'Thumb',
            0x169: 'MIPS little-endian WCE v2'
            }
        return switch[self._pe_machine]

    def get_pe_chars(self):
        """

        :return:
        """
        retval = ''
        characteristics = self._pe_characteristics
        if 0x0001 & characteristics:
            retval += '\n\tIMAGE_FILE_RELOCS_STRIPPED'
        if 0x0002 & characteristics:
            retval += '\n\tIMAGE_FILE_EXECUTABLE_IMAGE'
        if 0x0004 & characteristics:
            retval += '\n\tIMAGE_FILE_LINE_NUMS_STRIPPED'
        if 0x0008 & characteristics:
            retval += '\n\tIMAGE_FILE_LOCAL_SYMS_STRIPPED'
        if 0x0010 & characteristics:
            retval += '\n\tIMAGE_FILE_AGGRESSIVE_WS_TRIM'
        if 0x0020 & characteristics:
            retval += '\n\tIMAGE_FILE_LARGE_ADDRESS_AWARE'
        if 0x0080 & characteristics:
            retval += '\n\tIMAGE_FILE_BYTES_REVERSED_LO'
        if 0x0100 & characteristics:
            retval += '\n\tIMAGE_FILE_32BIT_MACHINE'
        if 0x0200 & characteristics:
            retval += '\n\tIMAGE_FILE_DEBUG_STRIPPED'
        if 0x0400 & characteristics:
            retval += '\n\tIMAGE_FILE_REMOVABLE_RUN_FROM_SWAP'
        if 0x0800 & characteristics:
            retval += '\n\tIMAGE_FILE_NET_RUN_FROM_SWAP'
        if 0x1000 & characteristics:
            retval += '\n\tIMAGE_FILE_SYSTEM'
        if 0x2000 & characteristics:
            retval += '\n\tIMAGE_FILE_DLL'
        if 0x4000 & characteristics:
            retval += '\n\tIMAGE_FILE_UP_SYSTEM_ONLY'
        if 0x8000 & characteristics:
            retval += '\n\tIMAGE_FILE_BYTES_REVERSED_HI'
            
        return retval
