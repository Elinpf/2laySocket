require "socket"
#require "ipaddr"

class Socket

	SIOCGIFINDEX = 0x8933

	ETH_P_ALL = [ 0x0003 ].pack("S>").unpack("S").first

	def bind_if(interface = 'eth0')
		ifreq = [ interface, '' ].pack("a16a16")
		self.ioctl(SIOCGIFINDEX, ifreq)
		index_str = ifreq[16, 4]

		eth_p_all_hbo = [ ETH_P_ALL ].pack("S").unpack("S>").first
		sll = [ Socket::AF_PACKET, eth_p_all_hbo, index_str ].pack("SS>a16")
		self.bind(sll)
	end

	#
	# Create  a Raw Socket by Base
	#
	def self.create_raw
		Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, Socket::ETH_P_ALL)
	end

	#
	# Create a bind interface Raw Socket
	#
	def self.create_if(interface)
		socket = Socket.create_raw
		socket.bind_if(interface)
		return socket
	end

	#
	# Create a bind Eth0 Raw Socket
	#
	def self.create_eth0
		socket = Socket.create_raw
		socket.bind_if('eth0')
		return socket
	end
		
	#
	# Get My Host PC IP address, return IPAddr
	#
	def self.getmyhostip(interface = 'eth0')
		`ifconfig #{interface}`.match(/inet addr:(.*)  Bcast/)[1]
	end

	#
	# Get My Host PC MAC address, return String
	#
	def self.getmyhostmac(interface = 'eth0')
		Socket.create_eth0.local_address.to_sockaddr[-6, 6]
		#`ifconfig #{interface}`.match(/HWaddr (.*)  /)[1]
	end
end

