require 'ipaddr'
#require 'test/unit'
require './socket2'
require './vtap.rb'

class TapTestHelper

	def initialize
		@tap_name = "ttap#{rand(9000) + 1000}"
		@tap = VTap.new(@tap_name)
		@ping_thread = nil
		@sock = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, Socket::ETH_P_ALL)
		@sock.bind_if @tap_name
	end

	attr_reader :tap_name, :tap, :sock, :ping_thread

	# This method spawns a thread 
	def answer_pings
		@ping_thread = Thread.new do 
			begin
				loop do 
					pkt = @tap.recv
					p pkt
=begin					
					icmp = icmp_offset(pkt)
					if icmp and pkt[icmp] == "\x08"  #type == Echo Request
						pkt[icmp, 1] = "\x00"
						pkt[26, 4], pkt[30, 4] = pkt[30, 4], pkt[26, 4]
						@tap.inject(pkt)
					end
=end			
				end
			rescue Object
				$stderr.puts $!
				$stderr.puts $@
				Kernel.exit(1)
			end
		end
	end

	def icmp_offset(pkt)
		return false unless pkt[12, 2] == "\x08\x00" and
				    pkt[23, 1] == "\x01"  # ethertype = IPv4  ICMP
		offset = 14 + ([ pkt[14].ord & 0x0F, 5 ].max * 4)
	end

	# Return the MAC address of the tap device
	def tap_mac
		@sock.local_address.to_sockaddr[-6,6]
	end

	# Wait for and return the next ping reply on the raw socket up to timeout
	def ping_reply(timeout = 1.0)
		loop do
			st = Time.now.to_f
			act = select([@sock], [], [@sock], timeout)
			return nil if !act or act.first.empty?
			pkt = @sock.recv(1514)
			icmp = icmp_offset(pkt)
			return pkt if icmp and pkt[icmp] == "\x00"
			timeout = timeout - Time.now.to_f + st
			return nil if timeout <= 0
		end
	end

	# Send the given raw layer-2 packet to the tap
	def inject(frame)
		@sock.send(frame, 0)
	end
end

#class TestSocket2 < Test::Unit::TestCase
class TestSocket2	
	def setup
		begin
			@tt = TapTestHelper.new
		rescue Errno::EPERM
			$stderr.puts "You must be root to create raw sockets"
			Kernel.exit(1)
		end
		
		# Tell the test tap to respond to ping packets
		@tt.answer_pings

		@ping = "\xFF\xFF\xFF\xFF\xFF\xFF\x00\f)\x88\x06\\\b\x06\x00\x01\b\x00\x06\x04\x00\x01\x00\f)\x88\x06\\\xC0\xA8\x12\x88\xFF\xFF\xFF\xFF\xFF\xFF\xC0\xA8\x12\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

	end

	# Inject the ping, wait for a reply
	def test_ping
	@tt.sock.send(@ping, 0)
=begin
		pong = @tt.ping_reply
		assert_equal(42, pong.length)
		assert_equal(pong[0, 6], @tt.tap_mac)
		assert_equal(pong[30, 4], @ping[26, 4])
		assert_equal(pong[26, 4], @ping[30, 4])
=end
	end
end
