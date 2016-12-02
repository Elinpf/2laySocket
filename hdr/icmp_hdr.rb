
require_relative "../core.rb"

##
#
#ICMP Header about Type
#
##
=begin
module ICMP_TYPE
	ICMP_ECHOREPLAY		= 0	#Echo Replay
	ICMP_DEST_UNREACH	= 3 	#Destination Unreachable
	ICMP_SOURCE_QUENCH	= 5	#Source Quench
	ICMP_REDIRECT		= 5	#Redirect (change route)
	ICMP_ECHO		= 8	#Echo Request
	ICMP_TIME_EXCEEDED	= 11	#Time Exceeded
	ICMP_PARAMETERPROB	= 12 	#Parameter Problem
	ICMP_TIMESTAMP		= 13	#Timestamp Request
	ICMP_TIMESTAMPREPLY	= 14	#Timestamp Reply
	ICMP_INFO_REWUEST	= 15	#Information Request
	ICMP_INFO_REPLY		= 16 	#Information Repay
	ICMP_ADDRESS		= 17	#Address Mask Request
	ICMP_ADDRESSREPLY	= 18 	#Address Mask Reply
end

module ICMP_CODE
	#
	#Codes for UNREACH
	#
	ICMP_NET_UNREACH	= 0	#Network Unreachable
	ICMP_HOST_UNREACH	= 1 	#Host Unreachable
	ICMP_PROT_UNREACH	= 2	#Protocol Unreachable
	ICMP_PORT_UNREACH	= 3	#Port Unreachable
	ICMP_FRAG_NEEDED	= 4	#Fragmentation Needed/DF set
	ICMP_SR_FAILED		= 5	#Source Route Failed
	ICMP_NET_UNKNOW		= 6	#Network Unknow
	ICMP_HOST_UNKNOW	= 7	#Host Unknow
	ICMP_HOST_ISOLATED	= 8
	ICMP_NET_ANO 		= 9
	ICMP_HOST_ANO		= 10
	ICMP_NET_UNR_TOS	= 11
	ICMP_HOST_UNR_TOS	= 12
	ICMP_PKT_FILTERED	= 13	#Packet filtered
	ICMP_PREC_VIOLATION	= 14	#Precedence violation
	ICMP_PREC_CUTOFF	= 15	#Precedence cut off
	ICMP_NR_UNREACH		= 15	#instead of hardcoding immediate value

	#
	#Codes for REDIRECT
	#
	ICMP_REDIR_NET		= 0	#Redirect Net ICMP_REDIR_HOST		= 1	#Redirect Host
	ICMP_REDIR_NETTOS	= 2	#Redirect Net for TOS
	ICMP_REDIR_HOSTTOS	= 3	#Redirect Host for TOS

	#
	#Codes for TIME_EXCEEDED
	#
	ICMP_EXC_TTL		= 0	#TTL count exceeded
	ICMP_EXC_FRAGTIME	= 1	#Fragment Reass time exceeded
end
=end

##
#
#ICMP Header about Struct
#
#
#
# ==== Header Definition
#
#   Int8    :icmp_type                        # Type
#   Int8    :icmp_code                        # Code
#   Int16   :icmp_sum    Default: calculated  # Checksum
#   String  :body
#
##
class ICMPHeader < Struct.new(:icmp_type, :icmp_code, :icmp_sum, :icmp_id, :icmp_seq, :body)
	
	include StructPf

	def initialize(args={})
		super(
			Int8.new(args[:icmp_type] || 8),
			Int8.new(args[:icmp_code] || 0),
			Int16.new(args[:icmp_sum] || icmp_calc_sum),
			Int16.new(args[:icmp_id]  || 1),
			Int16.new(args[:icmp_seq] || rand(2**16)),
			StructPf::StringPf.new.read(args[:body])
		     )
	end

	#
	#Return the object in String from, get All icmp_hdr String
	#
	def to_s
		self.to_a.map {|x| x.to_s}.join
	end

	#
	#Read the Giving String
	#
	def read str
		force_binary str
		return self if str.nil?
		self[:icmp_type].read str[0,1]
		self[:icmp_code].read str[1,1]
		self[:icmp_sum].read  str[2,2]
		self[:icmp_id].read   str[4,2]
		self[:icmp_seq].read  str[6,2]
		self[:body].read str[8,str.size]
		self
	end

	#
	#Set icmp_type value 
	#
	def icmp_type= i
		typecast("icmp_type", i)
	end	

	#
	#Get icmp_type value
	#
	def icmp_type
		self[:icmp_type].to_i
	end

	#
	#Set icmp_code value
	#
	def icmp_code= i
		typecast("icmp_code", i)
	end

	#
	#Get icmp_code value
	#
	def icmp_code
		self[:icmp_code].to_i
	end

	#
	#Set default check_sum by self or cacl_check_sum
	#
	def icmp_sum= i
		typecast("icmp_sum", i)
	end

	#
	#Get icmp_sum
	#
	def icmp_sum
		self[:icmp_sum].to_i
	end

	def icmp_sum_readable
		"0x%04x" % icmp_sum
	end

	#
	#Calc the icmp checksum
	#
	def icmp_calc_sum
		checksum = (icmp_type.to_i << 8)        + icmp_code.to_i
		chk_body = (body.to_s.size % 2 == 0 ? body.to_s : body.to_s + "\x00")
		if 1.respond_to? :ord
			chk_body.scan(/../).map { |x| (x[0].ord << 8) + x[1].ord }.each { |y| checksum += y }
	       else
			chk_body.scan(/../).map { |x| (x[0] << 8) + x[1] }.each { |y| checksum += y }
		end
		checksum = checksum % 0xffff
		checksum = 0xffff - checksum
		checksum == 0 ? 0xffff : checksum
	end

	def icmp_recalc(args=:all)
		self.icmp_sum = self.icmp_calc_sum
	end

	#
	# Set the ICMP Identifier
	#
	def icmp_id= i
		typecast "icmp_id", i
	end

	#
	# Get the ICMP Identifier
	#
	def icmp_id
		self[:icmp_id].to_i
	end

	#
	# Set the ICMP Sequence
	#
	def icmp_seq= i
		typecast "icmp_seq", i
	end

	#
	# Get the ICMP Sequence
	#
	def icmp_seq
		self[:icmp_seq].to_i
	end
end 	#class ICMPHeader


require_relative "./packet.rb"
class ICMPPacket < PacketPf

	attr_accessor :eth_header, :ip_header, :icmp_header

	def self.can_parse? str
		return false unless str.size >= 42
		return false unless EthPacket.can_parse? str
		return false unless IPPacket.can_parse?  str
		return false unless str[23,1] == "\x01"
		true
	end

	def read(str=nil, args={})
		raise "Can't parse" unless self.class.can_parse? str
		@eth_header.read str
		@ip_header.read str[14,str.size]
#warning: to_s
		@icmp_header.read(@ip_header.body.to_s)
		self.icmp_reclac(:all) if args[:fix] || args[:recalc]
		self
	end

	def initialize(args={})
		@eth_header  = EthHeader.new(args).read(args[:eth])
		@ip_header   = IPHeader.new(args).read(args[:ip])
		@ip_header.ip_proto = 1
		@icmp_header = ICMPHeader.new(args).read(args[:icmp])
		
		@ip_header.body = @icmp_header
		@eth_header.body = @ip_header

		@headers = [@eth_header, @ip_header, @icmp_header]
		super
	end

	def peek_fromt
		peek = ["IC  "]
		peek << "%-5d" % self.to_s.size
		type = 	case self.icmp_type.to_i
			when 8
				"ping"
			when 0
				"pong"
			else
				"%02x-%02x" % [self.icmp_type, self.icmp_code]
			end
		peek << "%-21s" % "#{self.ip_saddr}:#{type}"
		peek << "->"
		peek << "%21s" % self.ip_daddr
		peek << "%23s" % "I:"
		peek << "%04x" % self.ip_id
		peek.join
	end
end 	#class ICMPPacket
