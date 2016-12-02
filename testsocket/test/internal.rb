require "./socket3.rb"
require "ipaddr"

class TestSocket3
	def initialize
		@sock = Socket.new(Socket::AF_PACKET, Socket::SOCK_RAW, Socket::ETH_P_ALL)
		@sock.bind_if 'eth0'
		setup
	end
	attr_reader :sock

	def tap_mac
		@sock.local_address.to_sockaddr[-6, 6]
	end

	def setup
		@ping = [
			# Ethernet II
			tap_mac,
			tap_mac,
			[ 0x0800 ].pack("n"),

			# IP Header
			[ 0x45, 0, 20 + 8 ].pack("CCn"),
			[ rand(2**16), 0 ].pack("nn"),
			[ 61, 1, rand(2**16) ].pack("CCn"),
			IPAddr.new('192.168.18.136').hton,
			IPAddr.new('192.168.18.1').hton,

			# ICMP
			[ 8, 0, 0, 0 ].pack("CCnN")
		].join
	end

	def test_ping
		@sock.send(@ping, 0)
	end
end
