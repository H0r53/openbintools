#!/usr/bin/python3

"""
    File:
        - magictool.py

    Authors:
        - Jacob Mills,
        - Brandon Everhart,
        - Taylor Shields

    Date: 11/25/2018

    Description:
        - A utility for identifying files by their magic number association with known file types
        - Usage:
            data = open('filename','rb').read()
            magic_tool = MagicTool()
            magic_tool.find_magic(data)

    Changelog:
        - 9/17 Created
        - 11/25 Documented
        - 11/25 Cleaned formatting based on PyCharm, PyLint3, PEP8
        - 11/25 Pylint score 2.71/10 --> 3.56/10
            Note:
                Ignored "Line too long" for readability purposes
                Ignored "Too few public methods" for
                Ignored "Too many statements" for
"""


def docs():
    """
    Function:
        magictool.docs()

        Description:
            Prints all docstrings related to this file.

        Parameters:
            - None

        Return:
            - None
    """
    print(__doc__)
    print(docs.__doc__)
    print(FileObject.__init__.__doc__)
    print(MagicTool.__init__.__doc__)
    print(MagicTool.find_magic.__doc__)
    print(MagicTool.loadfiles.__doc__)
    print(FileUtils.hexstr2hexarray.__doc__)


class FileObject():
    """
    Class:
        magictool.FileObject

        Description:
            -

        Parameters:
            - None

        Functions:
            - __init__()
    """
    def __init__(self, description, offset, extensions, magic):
        """
        Function:
            magictool.FileObject.__init__()

        Description:
            -

        Parameters:
            - description:
                Description - ,
                Data Type - ,
                Requirement - mandatory,
                Argument Type - Positional (1st)
            - offset:
                Description - ,
                Data Type - ,
                Requirement - mandatory,
                Argument Type - Positional (2nd)
            - extensions:
                Description - ,
                Data Type - ,
                Requirement - mandatory,
                Argument Type - Positional (3rd)
            - magic:
                Description - ,
                Data Type - ,
                Requirement - mandatory,
                Argument Type - Positional (4th)

        Return:
            - None
        """
        self.description = description
        self.offset = offset
        self.extensions = extensions
        self.magic = magic


class MagicTool():
    """
    Class:
        magictool.MagicTool

        Description:
            -

        Parameters:
            - None

        Functions:
            - __init__()
            - find_magic()
            - loadfiles()
    """
    def __init__(self):
        """
        Function:
           magictool.MagicTool.__init__()

        Description:
            - Creates list of file magic numbers by running magictool.loadfiles().

        Parameters:
            - None

        Return:
            - None
        """
        self.files = []
        self.loadfiles()

    def find_magic(self, sourcebytes):
        """
        Function:
            magictool.MagicTool.find_magic()

        Description:
            -

        Parameters:
            - sourcebytes:
                Description - ,
                Data Type - ,
                Requirement - mandatory,
                Argument Type - Positional (1st)

        Return:
            - retval:
                Description -
                Data Type -
        """
        retval = ""
        matches = 0
        for file in self.files:
            found = True
            for i in range(0, len(file.magic)):
                if file.offset + i > len(sourcebytes):
                    found = False
                    break
                if file.magic[i] != sourcebytes[file.offset + i]:
                    found = False
                    break
            if found:
                retval += "{}\n".format(file.description)
                matches += 1

        if matches < 1:
            retval = "No matches found. This may be data or text."

        return retval

    def loadfiles(self):
        """
        Function:
            magictool.MagicTool.loadfiles()

        Description:
            - List of different magic numbers with their associated file type information.
            - Note: Sources defined from data on
            https://en.wikipedia.org/wiki/List_of_file_signatures

        Parameters:
            - None

        Return:
            - None
        """
        self.files.append(FileObject("Libpcap File Format", 0x0, ["pcap"], [0xa1, 0xb2, 0xc3, 0xd4]))
        self.files.append(FileObject("Libpcap File Format", 0x0, ["pcap"], [0xd4, 0xc3, 0xb2, 0xa1]))
        self.files.append(FileObject("PCAP Next Generation Dump File Format", 0x0, ["pcapng"], [0x0a, 0x0d, 0x0d, 0x0a]))
        self.files.append(FileObject("RedHat Package Manager (RPM) package", 0x0, ["rpm"], [0xed, 0xab, 0xee, 0xdb]))
        self.files.append(FileObject("Amazon Kindle Update Package", 0x0, ["bin"], [0x53, 0x50, 0x30, 0x31]))
        self.files.append(FileObject("IBM Storyboard bitmap file", 0x0, ["PIC", "PIF", "SEA", "YTR"], [0x53, 0x50, 0x30, 0x31]))
        self.files.append(FileObject("PalmPilot Database/Document File ", 11, ["PDB"], [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))
        self.files.append(FileObject("Palm Desktop Calendar Archive", 0x0, ["DBA"], [0xBE, 0xBA, 0xFE, 0xCA]))
        self.files.append(FileObject("Palm Desktop To Do Archive", 0x0, ["DBA"], [0x00, 0x01, 0x42, 0x44]))
        self.files.append(FileObject("Palm Desktop Calendar Archive", 0x0, ["TDA"], [0x00, 0x01, 0x44, 0x54]))
        self.files.append(FileObject("Palm Desktop Data File (Access format)", 0x0, [""], [0x00, 0x01, 0x00, 0x00]))
        self.files.append(FileObject("Computer icon encoded in ICO file format", 0x0, ["ico"], [0x00, 0x00, 0x01, 0x00]))
        self.files.append(FileObject("3rd Generation Partnership Project 3GPP and 3GPP2 multimedia files", 0x4, ["3gp", "3g2"], [0x66, 0x74, 0x79, 0x70, 0x33, 0x67]))
        self.files.append(FileObject("Compressed file (often tar zip) using Lempel-Ziv-Welch algorithm", 0x0, ["z", "tar.z"], [0x1f, 0x9d]))
        self.files.append(FileObject("Compressed file (often tar zip) using LZH algorithm", 0x0, ["z", "tar.z"], [0x1f, 0xa0]))
        self.files.append(FileObject("File or tape containing a backup done with AmiBack on an Amiga", 0x0, ["bac"], [0x42, 0x41, 0x43, 0x4B, 0x4D, 0x49, 0x4B, 0x45, 0x44, 0x49, 0x53, 0x4B]))
        self.files.append(FileObject("Compressed file using Bzip2 algorithm ", 0x0, ["bz2"], [0x42, 0x5a, 0x68]))
        self.files.append(FileObject("Image file encoded in the Graphics Interchange Format (GIF)", 0x0, ["gif"], [0x47, 0x49, 0x46, 0x38, 0x37, 0x61]))
        self.files.append(FileObject("Image file encoded in the Graphics Interchange Format (GIF)", 0x0, ["gif"], [0x47, 0x49, 0x46, 0x38, 0x39, 0x61]))
        self.files.append(FileObject("Tagged Image File Format", 0x0, ["tif", "tiff"], [0x49, 0x49, 0x2A, 0x00]))
        self.files.append(FileObject("Tagged Image File Format", 0x0, ["tif", "tiff"], [0x4D, 0x4D, 0x00, 0x2A]))
        self.files.append(FileObject("Canon RAW Format Version 2", 0x0, ["cr2"], [0x49, 0x49, 0x2A, 0x00, 0x10, 0x00, 0x00, 0x00, 0x43, 0x52]))
        self.files.append(FileObject("Kodak Cineon image", 0x0, ["cin"], [0x80, 0x2A, 0x5F, 0xD7]))
        self.files.append(FileObject("Compressed file using Rob Northen Compression (version 1) algorithm ", 0x0, [""], [0x52, 0x4E, 0x43, 0x01]))
        self.files.append(FileObject("Compressed file using Rob Northen Compression (version 2) algorithm ", 0x0, [""], [0x52, 0x4E, 0x43, 0x02]))
        self.files.append(FileObject("SMPTE DPX image (big endian)", 0x0, ["dpx"], [0x53, 0x44, 0x50, 0x58]))
        self.files.append(FileObject("SMPTE DPX image (little endian)", 0x0, ["dpx"], [0x58, 0x50, 0x44, 0x53]))
        self.files.append(FileObject("OpenEXR image", 0x0, ["exr"], [0x76, 0x2F, 0x31, 0x01]))
        self.files.append(FileObject("Better Portable Graphics format", 0x0, ["bpg"], [0x42, 0x50, 0x47, 0xfb]))
        self.files.append(FileObject("JPEG raw", 0x0, ["jpg", "jpeg"], [0xFF, 0xD8, 0xFF, 0xDB]))
        self.files.append(FileObject("JPEG JFIF", 0x0, ["jpg", "jpeg"], [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01]))
        self.files.append(FileObject("JPEG Exif", 0x0, ["jpg", "jpeg"], [0xFF, 0xD8, 0xFF, 0xE1, None, None, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00]))
        self.files.append(FileObject("IFF Interleaved Bitmap Image", 0x0, ["ilbm", "lbm", "ibm", "iff"], [0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x49, 0x4C, 0x42, 0x4D]))
        self.files.append(FileObject("IFF 8-Bit Sampled Voice", 0x0, ["8svx", "8sv", "svx", "snd", "iff"], [0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x38, 0x53, 0x56, 0x58]))
        self.files.append(FileObject("Amiga Contiguous Bitmap", 0x0, ["acbm", "iff"], [0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x41, 0x43, 0x42, 0x4D]))
        self.files.append(FileObject("IFF Animated Bitmap", 0x0, ["anbm", "iff"], [0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x41, 0x4E, 0x42, 0x4D]))
        self.files.append(FileObject("IFF CEL Animation", 0x0, ["anim", "iff"], [0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x41, 0x4E, 0x49, 0x4D]))
        self.files.append(FileObject("IFF Facsimile Image", 0x0, ["faxx", "fax", "iff"], [0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x46, 0x41, 0x58, 0x58]))
        self.files.append(FileObject("IFF Formatted Text", 0x0, ["ftxt", "iff"], [0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x46, 0x54, 0x58, 0x54]))
        self.files.append(FileObject("IFF Simple Musical Score", 0x0, ["smus", "smu", "mus", "iff"], [0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x53, 0x4D, 0x55, 0x53]))
        self.files.append(FileObject("IFF Musical Score", 0x0, ["cmus", "mus", "iff"], [0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x43, 0x4D, 0x55, 0x53]))
        self.files.append(FileObject("IFF YUV Image", 0x0, ["yuvn", "yuv", "iff"], [0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x59, 0x55, 0x56, 0x4E]))
        self.files.append(FileObject("Amiga Fantavision Movie", 0x0, ["iff"], [0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x46, 0x41, 0x4E, 0x54]))
        self.files.append(FileObject("Audio Interchange File Format", 0x0, ["aiff", "aif", "aifc", "snd", "iff"], [0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x41, 0x49, 0x46, 0x46]))
        self.files.append(FileObject("Index file to a file or tape containing a backup done with AmiBack on an Amiga", 0x0, ["idx"], [0x49, 0x4e, 0x44, 0x58]))
        self.files.append(FileObject("lzip compressed file", 0x0, ["lz"], [0x4c, 0x5a, 0x49, 0x50]))
        self.files.append(FileObject("DOS MZ executable file format and its descendants (including NE and PE)", 0x0, ["exe"], [0x4d, 0x5a]))
        self.files.append(FileObject("zip file format and formats based on it", 0x0, ["zip", "jar", "odt", "ods", "odp", "docx", "xlsx", "pptx", "vsdx", "apk", "aar"], [0x50, 0x4b, 0x03, 0x04]))
        self.files.append(FileObject("zip file format and formats based on it (empty archive)", 0x0, ["zip", "jar", "odt", "ods", "odp", "docx", "xlsx", "pptx", "vsdx", "apk", "aar"], [0x50, 0x4b, 0x05, 0x06]))
        self.files.append(FileObject("zip file format and formats based on it (spanned archive)", 0x0, ["zip", "jar", "odt", "ods", "odp", "docx", "xlsx", "pptx", "vsdx", "apk", "aar"], [0x50, 0x4b, 0x07, 0x08]))
        self.files.append(FileObject("RAR archive version 1.50 onwards", 0x0, ["rar"], [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]))
        self.files.append(FileObject("RAR archive version 5.0 onwards", 0x0, ["rar"], [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]))
        self.files.append(FileObject("Executable and Linkable Format", 0x0, [""], [0x7f, 0x45, 0x4c, 0x46]))
        self.files.append(FileObject("Image encoded in the Portable Network Graphics format", 0x0, ["png"], [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))
        self.files.append(FileObject("Java class file, Mach-O Fat Binary", 0x0, ["class"], [0xca, 0xfe, 0xba, 0xbe]))
        self.files.append(FileObject("UTF-8 encoded Unicode byte order mark", 0x0, [""], [0xEF, 0xBB, 0xBF]))
        self.files.append(FileObject("Mach-O binary (32-bit)", 0x0, [""], [0xfe, 0xed, 0xfa, 0xce]))
        self.files.append(FileObject("Mach-O binary (64-bit) ", 0x0, [""], [0xfe, 0xed, 0xfa, 0xcf]))
        self.files.append(FileObject("Mach-O binary (reverse byte ordering scheme, 32-bit)", 0x0, [""], [0xce, 0xfa, 0xed, 0xfe]))
        self.files.append(FileObject("Mach-O binary (reverse byte ordering scheme, 64-bit)", 0x0, [""], [0xcf, 0xfa, 0xed, 0xfe]))
        self.files.append(FileObject("Byte-order mark for text file encoded in little-endian 16-bit Unicode Transfer Format", 0x0, [""], [0xff, 0xfe]))
        self.files.append(FileObject("Byte-order mark for text file encoded in little-endian 32-bit Unicode Transfer Format", 0x0, [""], [0xff, 0xfe, 0x00, 0x00]))
        self.files.append(FileObject("PostScript document", 0x0, ["ps"], [0x25, 0x21, 0x50, 0x53]))
        self.files.append(FileObject("PDF document", 0x0, ["pdf"], [0x25, 0x50, 0x44, 0x46]))
        self.files.append(FileObject("Advanced Systems Format", 0x0, ["asf", "wma", "wmv"], [0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C]))
        self.files.append(FileObject("System Deployment Image, a disk image format used by Microsoft", 0x0, [""], [0x24, 0x53, 0x44, 0x49, 0x30, 0x30, 0x30, 0x31]))
        self.files.append(FileObject("Ogg, an open source media container format ", 0x0, ["ogg", "oga", "ogv"], [0x4f, 0x67, 0x67, 0x53]))
        self.files.append(FileObject("Photoshop Document file", 0x0, ["psd"], [0x38, 0x42, 0x50, 0x53]))
        self.files.append(FileObject("Waveform Audio File Format", 0x0, ["wav"], [0x52, 0x49, 0x46, 0x46, None, None, None, None, 0x57, 0x41, 0x56, 0x45]))
        self.files.append(FileObject("Audio Video Interleave video format", 0x0, ["avi"], [0x52, 0x49, 0x46, 0x46, None, None, None, None, 0x41, 0x56, 0x49, 0x20]))
        self.files.append(FileObject("MPEG-1 Layer 3 file without an ID3 tag or with an ID3v1 tag", 0x0, ["mp3"], [0xff, 0xfb]))
        self.files.append(FileObject("MP3 file with an ID3v2 container ", 0x0, ["mp3"], [0x49, 0x44, 0x33]))
        self.files.append(FileObject("BMP file", 0x0, ["bmp", "dib"], [0x42, 0x4d]))
        self.files.append(FileObject("ISO9660 CD/DVD image file", 0x8001, ["iso"], [0x43, 0x44, 0x30, 0x30, 0x31]))
        self.files.append(FileObject("Flexible Image Transport System (FITS)", 0x0, ["fits"], [0x53, 0x49, 0x4D, 0x50, 0x4C, 0x45, 0x20, 0x20]))
        self.files.append(FileObject("Free Lossless Audio Codec", 0x0, ["fLaC"], [0x66, 0x4c, 0x61, 0x43]))
        self.files.append(FileObject("MIDI sound file", 0x0, ["mid", "midi"], [0x4d, 0x54, 0x68, 0x64]))
        self.files.append(FileObject("Compound File Binary Format, a container format used for document by older versions of Microsoft Office", 0x0, ["doc", "xls", "ppt", "msg"], [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]))
        self.files.append(FileObject("Dalvik Executable", 0x0, ["dex"], [0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00]))
        self.files.append(FileObject("VMDK files", 0x0, ["vmdk"], [0x4b, 0x44, 0x4d]))
        self.files.append(FileObject("Google Chrome extension or packaged app", 0x0, ["crx"], [0x43, 0x72, 0x32, 0x34]))
        self.files.append(FileObject("FreeHand 8 document", 0x0, ["fh8"], [0x41, 0x47, 0x44, 0x33]))
        self.files.append(FileObject("AppleWorks 5 document", 0x0, ["cwk"], [0x05, 0x07, 0x00, 0x00, 0x42, 0x4F, 0x42, 0x4F, 0x05, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]))
        self.files.append(FileObject("AppleWorks 6 document", 0x0, ["cwk"], [0x06, 0x07, 0xE1, 0x00, 0x42, 0x4F, 0x42, 0x4F, 0x06, 0x07, 0xE1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]))
        self.files.append(FileObject("Roxio Toast disc image file", 0x0, ["toast"], [0x45, 0x52, 0x02, 0x00, 0x00, 0x00]))
        self.files.append(FileObject("Roxio Toast disc image file", 0x0, ["toast"], [0x8B, 0x45, 0x52, 0x02, 0x00, 0x00, 0x00]))
        self.files.append(FileObject("Apple Disk Image file", 0x0, ["dmg"], [0x78, 0x01, 0x73, 0x0D, 0x62, 0x62, 0x60]))
        self.files.append(FileObject("eXtensible ARchive format", 0x0, ["xar"], [0x78, 0x61, 0x72, 0x21]))
        self.files.append(FileObject("Windows Files And Settings Transfer Repository", 0x0, ["dat"], [0x50, 0x4D, 0x4F, 0x43, 0x43, 0x4D, 0x4F, 0x43]))
        self.files.append(FileObject("Nintendo Entertainment System ROM file", 0x0, ["nes"], [0x4E, 0x45, 0x53, 0x1A]))
        self.files.append(FileObject("tar archive", 0x101, ["tar"], [0x75, 0x73, 0x74, 0x61, 0x72, 0x00, 0x30, 0x30]))
        self.files.append(FileObject("tar archive", 0x101, ["tar"], [0x75, 0x73, 0x74, 0x61, 0x72, 0x20, 0x20, 0x00]))
        self.files.append(FileObject("Open source portable voxel file", 0x0, ["tox"], [0x74, 0x6F, 0x78, 0x33]))
        self.files.append(FileObject("Magic Lantern Video file", 0x0, ["MLV"], [0x4D, 0x4C, 0x56, 0x49]))
        self.files.append(FileObject("Windows Update Binary Delta Compression", 0x0, [""], [0x44, 0x43, 0x4D, 0x01, 0x50, 0x41, 0x33, 0x30]))
        self.files.append(FileObject("7-Zip File Format", 0x0, ["7z"], [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]))
        self.files.append(FileObject("GZIP", 0x0, ["gz", "tar.gz"], [0x1f, 0x8b]))
        self.files.append(FileObject("XZ compression utility using LZMA2 compression", 0x0, ["xz", "tar.xz"], [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00]))
        self.files.append(FileObject("LZ4 Frame Format", 0x0, ["lz4"], [0x04, 0x22, 0x4d, 0x18]))
        self.files.append(FileObject("Microsoft Cabinet file", 0x0, ["cab"], [0x4d, 0x53, 0x43, 0x46]))
        self.files.append(FileObject("Microsoft compressed file in Quantum format, used prior to Windows XP", 0x0, ["(ending in _)"], [0x53, 0x5A, 0x44, 0x44, 0x88, 0xF0, 0x27, 0x33]))
        self.files.append(FileObject("Free Lossless Image Format", 0x0, ["flif"], [0x46, 0x4C, 0x49, 0x46]))
        self.files.append(FileObject("Matroska media container, including WebM", 0x0, ["mkv", "mka", "mks", "mk3d", "webm"], [0x1A, 0x45, 0xDF, 0xA3]))
        self.files.append(FileObject("SEAN : Session Analysis", 0x0, ["stg"], [0x4D, 0x49, 0x4C, 0x20]))
        self.files.append(FileObject("DjVu document", 0x0, ["djvu", "djv"], [0x41, 0x54, 0x26, 0x54, 0x46, 0x4F, 0x52, 0x4D, None, None, None, None, 0x44, 0x4A, 0x56]))
        self.files.append(FileObject("DER encoded X.509 certificate", 0x0, ["djvu", "djv"], [0x30, 0x82]))
        self.files.append(FileObject("DICOM Medical File Format", 0x0, ["dcm"], [0x44, 0x49, 0x43, 0x4D]))
        self.files.append(FileObject("WOFF File Format 1.0", 0x0, ["woff"], [0x77, 0x4F, 0x46, 0x46]))
        self.files.append(FileObject("WOFF File Format 2.0", 0x0, ["woff2"], [0x77, 0x4F, 0x46, 0x32]))
        self.files.append(FileObject("eXtensible Markup Language", 0x0, ["XML"], [0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x20]))
        self.files.append(FileObject("WebAssembly binary format", 0x0, ["wasm"], [0x00, 0x61, 0x73, 0x6d]))
        self.files.append(FileObject("Lepton compressed JPEG image", 0x0, ["lep"], [0xcf, 0x84, 0x01]))
        self.files.append(FileObject("flash .swf (CWS)", 0x0, ["swf"], [0x43, 0x57, 0x53]))
        self.files.append(FileObject("flash .swf (FWS)", 0x0, ["swf"], [0x46, 0x57, 0x53]))
        self.files.append(FileObject("linux deb file", 0x0, ["deb"], [0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E]))
        self.files.append(FileObject("Google WebP image file", 0x0, ["webp"], [0x52, 0x49, 0x46, 0x46, None, None, None, None, 0x57, 0x45, 0x42, 0x50]))
        self.files.append(FileObject("U-Boot / uImage. Das U-Boot Universal Boot Loader", 0x0, [""], [0x27, 0x05, 0x19, 0x56]))
        self.files.append(FileObject("Rich Text Format", 0x0, ["rtf"], [0x7B, 0x5C, 0x72, 0x74, 0x66, 0x31]))
        self.files.append(FileObject("Microsoft Tape Format", 0x0, [""], [0x54, 0x41, 0x50, 0x45]))
        self.files.append(FileObject("MPEG Program Stream", 0x0, ["mpg", "mpeg"], [0x00, 0x00, 0x01, 0xba]))
        self.files.append(FileObject("MPEG-1 video and MPEG-2 video", 0x0, ["mpg", "mpeg"], [0x00, 0x00, 0x01, 0xb3]))
        self.files.append(FileObject("zlib No Compression/low", 0x0, ["zlib"], [0x78, 0x01]))
        self.files.append(FileObject("zlib Default Compression", 0x0, ["zlib"], [0x78, 0x9c]))
        self.files.append(FileObject("zlib Best Compression", 0x0, ["zlib"], [0x78, 0xda]))
        self.files.append(FileObject("Minecraft Level Data File (NBT)", 0x1, ["dat"], [0x1F, 0x8B, 0x08, 0x00]))
        self.files.append(FileObject("LZFSE - Lempel-Ziv style data compression algorithm using Finite State Entropy coding", 0x0, ["woff2"], [0x62, 0x76, 0x78, 0x32]))
        self.files.append(FileObject("Apache ORC (Optimized Row Columnar) file format", 0x0, ["orc"], [0x4f, 0x52, 0x43]))
        self.files.append(FileObject("Apache Avro binary file format", 0x0, ["avro"], [0x4F, 0x62, 0x6A, 0x01]))
        self.files.append(FileObject("RCFile columnar file format", 0x0, ["rc"], [0x53, 0x45, 0x51, 0x36]))
        self.files.append(FileObject("PhotoCap Object Templates", 0x0, ["p25", "obt"], [0x65, 0x87, 0x78, 0x56]))
        self.files.append(FileObject("PhotoCap Vector", 0x0, ["pcv"], [0x55, 0x55, 0xaa, 0xaa]))
        self.files.append(FileObject("PhotoCap Template", 0x0, ["pbt", "pdt", "pea", "peb", "pet", "pgt", "pict", "pjt", "pkt", "pmt"], [0x78, 0x56, 0x34]))
        self.files.append(FileObject("Apache Parquet columnar file format", 0x0, [""], [0x50, 0x41, 0x52, 0x31]))
        self.files.append(FileObject("Emulator Emaxsynth samples", 0x0, ["ez2"], [0x45, 0x4D, 0x58, 0x32]))
        self.files.append(FileObject("Emulator III synth samples", 0x0, ["ez3", "iso"], [0x45, 0x4D, 0x55, 0x33]))
        self.files.append(FileObject("Lua bytecode", 0x0, ["luac"], [0x1B, 0x4C, 0x75, 0x61]))
        self.files.append(FileObject("macOS file Alias", 0x0, ["alias"], [0x62, 0x6F, 0x6F, 0x6B, 0x62, 0x6F, 0x6F, 0x6B, 0x00, 0x00, 0x00, 0x00, 0x6D, 0x61, 0x72, 0x6B]))
        self.files.append(FileObject("Microsoft Zone Identifier for URL Security Zones", 0x0, ["Identifier"], [0x5B, 0x5A, 0x6F, 0x6E, 0x65, 0x54, 0x72, 0x61, 0x6E, 0x73, 0x66, 0x65, 0x72, 0x5D]))
        self.files.append(FileObject("Email Message var5", 0x0, ["eml"], [0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64]))
        self.files.append(FileObject("Tableau Datasource", 0x0, ["tde"], [0x20, 0x02, 0x01, 0x62, 0xA0, 0x1E, 0xAB, 0x07, 0x02, 0x00, 0x00, 0x00]))


class FileUtils():
    """
    Class:
        magictool.FileUtils

        Description:
            -

        Parameters:
            - None

        Functions:
            - hexstr2hexarray()
    """
    @staticmethod
    def hexstr2hexarray(data, delimiter=" "):
        """
        Function:
            magictool.FileUtils.hexstr2hexarray()

        Description:
            -

        Parameters:
            - data:
                Description - ,
                Data Type - ,
                Requirement - mandatory,
                Argument Type - Positional (1st)
            - delimiter:
                Description - ,
                Data Type - ,
                Requirement - optional(default=" ")
                Argument Type - Positional (2nd)

        Return:
            - retval:
                Description -
                Data Type -
        """
        tmp = data.split(delimiter)
        retval = "["
        for i in tmp:
            if i == "??":
                retval += "None"
            else:
                retval += "0x" + i
            if i is not tmp[len(tmp) - 1]:
                retval += ", "
        retval += "]"
        return retval


if __name__ == "__main__":
    docs()
