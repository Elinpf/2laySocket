require "./core"

class PingInit < ICMPPacket
	include Setup

	def initialize(args={})
		@sock = Socket.create_eth0
		super
	end

	def setup(opts={})
		super
	end

	# Send ICMP Packet
	def send
		@sock.send(self.to_s, 0)
	end
end 	#class PingInit

include Parser::Register
include Parser::Case

class Ping

	#
	# Register the Eth , IP Arguments by ./arguments
	#
	def initialize(*args)
		opt = {}
		opt.merge!(Parser::Register.eth_register)
		opt.merge!(Parser::Register.ip_register)
		opt.merge!(Parser::Register.icmp_register)
		opt.merge!(Parser::Register.def_register)

		@@ping_opt = Parser::Arguments.new(opt)
		@ping_init = PingInit.new.setup(
					:eth_src => Socket.getmyhostmac,
					:eth_dest => "00:50:56:C0:00:08",
					:ip_src  => Socket.getmyhostip.to_s,
					:icmp_type => 8,
					:icmp_code => 0,
					:icmp_id   => 1,
					:recalc  => true,
				)
	end

	def name 
		'Ping'
	end
	
	def cmd_ping(args = [])
		
		@setup_opt = {}
		@@ping_opt.parser(*args) do |opt,idx,val|
			case opt
				when "--icmp-type"
					@setup_opt[:icmp_type] = val.to_i
				when "--icmp-code"
					@setup_opt[:icmp_code] = val.to_i
				when "--icmp-badsum"
					@setup_opt[:icmp_sum] = false
				when "-h"
					@@ping_opt.usage
					return false
				else
					@setup_opt.merge!(Parser::Case.eth_case(opt,val))
					@setup_opt.merge!(Parser::Case.ip_case(opt,val))
					@setup_opt.merge!(Parser::Case.def_case(opt,val))
			end
		end
		
		@ping_init.setup(@setup_opt)
		
		# Check the checksum 
		@ping_init.setup(:ip_sum => @setup_opt[:ip_sum],
				 :icmp_sum => @setup_opt[:icmp_sum])
			
		@ping_init.send
	end

end

