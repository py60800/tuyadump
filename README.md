## tuyadump (experimental)

Tool to dump communication with tuya devices

# Warning

This tool has been developped while coding a GO API to control Tuya devices (Available here)[https://github.com/py60800/tuya].

Despite being the result of quick and dirty coding, I found it great for debugging tuya communication.

Thanks to Erik Montnemery (@emontnemery), tuyadump now supports 3.3 protocol.
If you encounter any issue, you can try the previous version (branch master).

# Prerequisites
Get the keys and ids of the tuya devices : [https://github.com/codetheweb/tuyapi/blob/master/docs/SETUP.md](https://github.com/codetheweb/tuyapi/blob/master/docs/SETUP.md)

# Acknowledgements

@codetheweb for reverse engineering tuya protocol

@google team for providing gopacket libraries

@emontnemery for providing clues and examples to support 3.3 protocol

and many others...

# Get and build (Linux)

Install libpcap dev package (i.e. `sudo apt install libpcap<version>dev`)

Get gopacket library:

`go get "github.com/google/gopacket"`

Get this library 

`go get "github.com/py60800/tuyadump"`

Build:

`go build tuyadump.go comm-msg.go  crypto.go  dodump.go`debug.go

# Run

Create a config file with the keys and id collected from tuya device (check example config for format)

To view traffic in real time
`sudo ./tuyadump  -C tuyaconfig.json`port 6668

To view trafic collected with tcpdump:
`tuyadump -C tuyaconfig.json -r dump.pcap`

-d option can be used to dump packets as hex data

