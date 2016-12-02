require_relative "../core.rb"
require_relative "./proto_conn.rb"
require_relative "./capture.rb"

module Conn
class Conn
	
	# Use to give Class the Protocol and Default value
	include Proto

 	def initialize(args={})
		@sock = Socket.create_eth0
		@cap = Capture.new
	end

	# :packet is use to save Packet.new and the capture
	attr_accessor :sock, :packet  
	# :cap is use to recv packet 
	attr_accessor :cap
	# :argument => Parser::Arguments.new	
	attr_accessor :arguments

	#
	# The Register is 
	#
	def register(packet_class)
		@packet = packet_class
		reg = Parser::Register.new.inject(@packet)
		@arguments = Parser::Arguments.new(reg)
		self
	end

	#
	# start capture
	#
	def capture
		@cap.run
	end
	#
	# Return the String about send and recv packet
	#
	def to_s
		self.packet.to_s	
	end

	#
	# Read the Given or Recv Packet
	#
	def read str	
		self.packet.read str
	end

	#
	# Peek_fromt, Printf the peek_fromt when send or recv packet
	#
	def peek_fromt
		begin
			self.packet.peek_fromt
		rescue 
			raise ArgumentError, "This Protocol has not peek_fromt, Please contact the Administrator"
		end
	end

	#
	# This Setup is extend the Packet method => include? and Parser::Setup
	# Use clone means don't modify the default packet
	#
	def setup(opts={})
		@packet.extend(Parser::Setup)
		@packet.clone.setup(opts)
	end
	
	#
	# Only help to see the STDOUT
	#
	def inspect
		@packet.inspect
	end

end 	#class Conn
end 	#module Conn
