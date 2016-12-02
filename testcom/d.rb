require "socket"

so = Socket.open(Socket::AF_PACKET, Socket::SOCK_RAW, [0x0003].pack("S>").unpack("S").first)

so.recvfrom(2048)
