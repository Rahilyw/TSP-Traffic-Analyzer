===========================================================================
CS-361 Computer Communications and Networks (Spring 2026)
Programming Assignment: 2 [TCP Traffic Analysis]
===========================================================================

Name: Rahil Wijeyesekera
Student ID: V01041863

Description
----------------------------------------------------------------------------
This project contains a Python 3 script (`tcp_analyzer.py`) designed to parse 
and analyze a binary PCAP trace file. It manually unpacks the global, packet, 
Ethernet, IPv4, and TCP headers to track the state of duplex TCP connections. 
It calculates summary information including connection states, durations, packet 
and byte counts, and round-trip times (RTT).

Included Files
----------------------------------------------------------------------------
1. tcp_analyzer.py  The main Python script for parsing and analyzing the PCAP file.
2. readme.txt       This file, containing execution instructions.


System Requirements
-----------------------------------------------------------------------------
This script is designed to run on the University of Victoria's Linux server 
(linux.csc.uvic.ca). It uses strictly standard Python 3 libraries (`struct`, 
`socket`, `sys`) and requires NO third-party packages to execute!


Execution Instructions
-----------------------------------------------------------------------------
1. Transfer the `tcp_analyzer.py` file and your target `.cap` trace file to 
   the linux.csc.uvic.ca server.
2. Ensure you are using Python 3 to run the script. 
3. Execute the script from the command line, passing the PCAP file as the 
   first argument.

Command Format
$ python3 tcp_analyzer.py <path_to_pcap_file>

Example
$ python3 tcp_analyzer.py sample-capture-file.cap

Output
============================================================================
The script will output the results directly to the standard output (console) 
following the strict formatting requirements outlined in `outputformat.pdf`, 
divided into sections A, B, C, and D.

