telnetlogger(8) -- Tiny telnet honeypot
=======================================

## SYNOPSIS

telnetlogger <options>

## DESCRIPTION

**telnetlogger** is a small daemon that accepts incomiong Telnet
connections and logs the username/password attempts. Specifically,
it is designed to log attempts from the Mirai IoT worm.

There are three output formats: just the passwords, just the IP
addresses, or a CSV output containing both.

The way I run this is on a Raspberry Pi with the following
parameters:

	telnetlogger -c telnet.csv -p null -i null -l 2323

I then use the firewall to redirect incoming port 23 to my network
to the Raspberry Pi on port 2323.

## OPTIONS

  * `-c <filename>`: An output file in CSV format containing the
	time, IP address, username, and password for each attempt.
	A filename of `-` means <stdout>, a filename of 
	`null` means no output.

  * `-i <filename>`: An output file for the IPv4/IPv6 addresses logged
	by the daemon. A filename of `-` means <stdout>, a filename of 
	`null` means no output. If no filename given, the passwords will
	be printed to the command-line.

  * `-p <filename>`: An output file for the passwords logged
	by the daemon. A filename of `-` means <stdout>, a filename of 
	`null` means no output. If no filename given, the passwords will
	be printed to the command-line.

  * `-l <port>`: A port number to listen on. Often, people will setup the
	service to listen on a high-numbered port, such as 2323, then use
	firewall rules to redirect the Telnet port 23 to this high-numbered
	port. If not specified, by default port 23 will be used. This may
	require root priveleges to run on low-numbered ports.
    
## OUTPUT FORMAT 

The internet addresses are output in either IPv4 or IPv6 format as
appropriate. Usernames and passwords are filter non-printable characters
and some punctuation, replacing them with the standard \xXX format.

The CSV format has the columns:

	time_t, timestamp, address, username, password

An example line is:

	1478398395,2016-11-06 02:13:15,127.0.0.1,foo,bar

## COMPATIBILITY

The tool runs on Windows and Linux, but should run on most other systems
as well.

## AUTHORS

This tool was written by Robert Graham. The source code is available at
https://github.com/robertdavidgraham/telnetlogger.
