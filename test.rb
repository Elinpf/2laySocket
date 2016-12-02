load "core.rb"

send = Sub_Program::ARP.new("--arp-opcode","2","--arp-src-mac","FA:FA:FA:FA:FA:FA","192.168.18.1")
send.inject
