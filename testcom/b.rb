  require 'socket'

 class VLink
 	ETH_P_ALL	= 0x0003
	SIOCGIFINDEX	= 0x8933
	SIOCGIFHWADDR 	= 0x8927

	def initialize(interface = 'eth0')
		@eth_p_all_hbo = [ ETH_P_ALL ].pack("S>").unpack("S").first
		@raw = Socket.open(Socket::AF_PACKET, Socket::SOCK_RAW, @eth_p_all_hbo)

		# Use an ioctl to get the MAC address of the provided interface
		ifreq = [ interface, '' ].pack("a16a16")
		@raw.ioctl(SIOCGIFHWADDR, ifreq)
		@src_mac = ifreq[18, 6]

		# Also get the system's internal interface index value
		ifreq = [ interface, '' ].pack("a16a16")
		@raw.ioctl(SIOCGIFINDEX, ifreq)
		index_str = ifreq[16, 4]

		# Build our sockaddr_ll struct so we can bind to this interface. The Struc
		# is defined in linux/if_packet.h and requires the interface index.
		@sll = [ Socket::AF_PACKET, ETH_P_ALL, index_str ].pack("SS>a16")
		@raw.bind(@sll)
	end
		attr_reader :raw, :src_mac

	# Send raw data out of our socket. Provide an ethernet frame
	# starting at the 6-btye destination MAC address
	def inject(frame)
		@raw.send(frame, Socket::SOCK_RAW, @sll)
	end

	# Receive and return one raw frame
	def recv(maxlen = 2048)
		@raw.recvfrom(maxlen).first
	end

end
	#
