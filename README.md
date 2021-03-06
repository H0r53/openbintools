# COP5570 Term Group Project
## Our Team
- Jacob Mills
- Brandon Everhart
- Taylor Shields

## Project Type
OpenBinTools – A distributed platform for binary analysis. This project intends to establish an open-source suite of tools useful for binary analysis utilizing client-server architecture and concurrent, parallel, and distributed computing.

## Project Topic
Binary analysis is useful for reverse engineers, software developers, and security professionals. This project intends to combine a variety of binary analysis techniques into a single portable platform offering web services to distribute the workload of binary processing and minimize dependencies and resource requirements for performing binary analysis on a given machine or operating system. The topical scope of this project includes binary analysis, malware identification, and reverse engineering.

## Detailed Objectives (with planned steps to achieve)
   - Create a client-server architecture to perform binary analysis
     - Enable hybrid asymmetric encryption using the Diffie-Hellman key exchange and the Blowfish encryption algorithm
     - Enable multi-threading so multiple clients can be serviced at once
     - Allow for arbitrarily-sized datastreams to be transmitted without error
   - Enable portability across systems
     - Allow for the client to run in two modes: a menu driven mode and a command line interface
     - Minimize dependencies and resource requirements for the client-server by offloading them to the server
     - The client should have cross-platform support for any environment using Python 3
     - Allow for easy installation of utilities and dependencies for the client and server
   - Identify the file type of binaries
     - Create a utility for recognition of file types based on magic number
   - Develop a simple loader to recognize binary segments
     - Enable support for ELF and PE recognition and parsing using parallel processing
   - Recognize malware using binary signatures
     - Utilize the VirusTotal API for recognition of known malware signatures
   - Identify strings, functions, and symbols within a binary
     - Combine functionality from utilities such as radare2, strings, and custom code for parsing and recognizing strings, functions, and symbols

## Current Status
   - Created client and server architecture using Python 3
     - The server uses multi-threading to support multiple connections concurrently
     - Developed a class for facilitating the accurate transmission of arbitrarily-sized datastreams
     - Implemented asymmetric encryption using the Diffie-Hellman key exchange and the Blowfish encryption algorithm
   - Developed a tool for file recognition based on magic numbers
     - Implemented tools for server-side binary disassembly
   - Created a menu-driven client interface for interacting with local binaries and the server
     - Enabled support for binary loading, disassembly, and file recognition
