require 'socket'

class Socket
	SIOCGIFINDEX 	= 0x8933	# bits/ioctls.h    name -> if_index mapping
	SIOCGIFHWADDR	= 0x8927	# linux/sockios.h  get hardware address

	# linux/if_ether.h, needs to be antive-endian uint16_t
	ETH_P_ALL = [ 0x0003 ].pack("S>").unpack("S").first

	# Bind a layer-2 raw socket to the given interface
	def bind_if interface
		# Get the system's internal interface index value
		ifreq = [ interface, '' ].pack("a16a16")
		self.ioctl(SIOCGIFINDEX, ifreq)
		index_str = ifreq[16, 4]

	#
	# Build our sockaddr_11 struct so we can bind to this interface. The struct
	# is defined in linux/if_packet.h and requires the interface index
	#
	eth_p_all_hbo = [ ETH_P_ALL ].pack("S").unpack("S>").first
	sll = [ Socket::AF_PACKET, eth_p_all_hbo, index_str ].pack("SS>a16")
	self.bind(sll)
	end
end 	#class Socket
