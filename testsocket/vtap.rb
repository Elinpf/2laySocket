require 'socket'

class VTap
	ETH_P_ALL	=	0x0003	# linux/if_ether.h
	SIOCGIFHWADDR	=	0x8927	# linux/sockios.h
	IFF_TAP		= 	0x0002	# linux/if_tun.h
	TUNSETIFF	=   0x400454ca	# _IOW('T', 202, int)
	SIOCGIFFLAGS	= 	0x8913	# from linux/sockios.h
	SIOCSIFFLAGS	=	0x8914	# from linux/sockios.h
	IFF_UP		= 	0x0001	# from net/if.h
	IFF_RUNNING	= 	0x0040	# from net/if.h

	def initialize(tap = 'tinytap')
		@tap = tap
		@eth_p_all_hbo = [ ETH_P_ALL ].pack("S>").unpack("S").first

		# First let's define our ifreq structure. It's 32 bytes - the first 16
		# hold the tap name, and the second 16 hold (in our case) the flags.
		ifreq = [ tap, IFF_TAP, '' ].pack('a16S<a14')

		# Open the clone device
		clone_dev = File.open('/dev/net/tun', 'w+')

		# Create our device and get the MAC address
		clone_dev.ioctl(TUNSETIFF, ifreq.dup)
		mac_ifreq = ifreq.dup
		clone_dev.ioctl(SIOCGIFHWADDR, mac_ifreq)
		@tap_mac = mac_ifreq[18, 6]

		# Mark the device as up
		upfd = Socket.open(Socket::AF_PACKET, Socket::SOCK_RAW, @eth_p_all_hbo)
		upfd.ioctl(SIOCGIFFLAGS, ifreq)		# get flag settings
		flags = ifreq[16, 2].unpack("S").first | IFF_UP | IFF_RUNNING
		ifreq[16, 2] = [ flags ].pack("S")
		upfd.ioctl(SIOCSIFFLAGS, ifreq)		# set flag values bace
		upfd.close
		@raw = clone_dev
	end

	attr_reader :tap, :raw, :tap_mac

	def inject(frame)
		tap_hdr = ['', frame[12, 2] ].pack('a2a2')
		@raw.write(tap_hdr + frame)
		@raw.flush
	end

	# Receive and return one raw frame
	def recv(maxlen = 2048)
		@raw.readpartial(maxlen)[4..-1]
	end
end
