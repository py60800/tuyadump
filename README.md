## tuyadump (experimental)

Tool to dump communication with tuya devices

# warning

This tool is the result of quick and dirty coding. I found it useful for debugging tuya communication.

As of now, only version "3.1" protocol is supported

# prerequisites
Get the keys and ids of the tuya devices : (See code the web)[https://github.com/codetheweb/tuyapi/blob/master/docs/SETUP.md]

# acknowledgements

@codetheweb for reverse engineering tuya protocol

@google team for providing gopacket libraries

and many others...

# Get and build (Linux)

Install libpcap dev package (i.e. `sudo apt install libpcap<version>dev`)

Get gopacket library:

`go get "github.com/google/gopacket"`

Get this library 

`go get "github.com/py60800/tuyadump"`

Build:

`go build tuyadump.go comm-msg.go  crypto.go  dodump.go`

# Run

Create a config file with the keys and id collected from tuya device (check example config for format)

To view traffic in real time
`sudo tuyadump port 6668 -C tuyaconfig.json`

To view trafic collected with tcpdump:
`tuyadump -C tuyaconfig.json -r dump.pcap`

