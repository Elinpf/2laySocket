require_relative "../core.rb"

# ==== Header Definition
#   
#        Int16   :arp_hw          Default: 1       # Ethernet
#        Int16   :arp_proto,      Default: 0x8000  # IP
#        Int8    :arp_hw_len,     Default: 6
#        Int8    :arp_proto_len,  Default: 4
#        Int16   :arp_opcode,     Default: 1     
#		  # 1: Request, 2: Reply, 3: Request-Reverse, 4: Reply-Reverse
#        EthMac  :arp_src_mac                      # From eth.rb
#        Octets  :arp_src_ip                       # From ip.rb
#        EthMac  :arp_dst_mac                      # From eth.rb
#        Octets  :arp_dst_ip                       # From ip.rb
#        String  :body


class ARPHeader < Struct.new(   :arp_hw, :arp_proto, :arp_hw_len, :arp_proto_len,
				:arp_opcode,
				:arp_src_mac, :arp_src_ip,
				:arp_dest_mac, :arp_dest_ip,
				:body)

	include StructPf

	def initialize(args={})
		super(
			Int16.new(args[:arp_hw] || 1),
			Int16.new(args[:arp_proto] || 0x0800),
			Int8.new(args[:arp_hw_len] || 6),
			Int8.new(args[:arp_proto_len] || 4),
			Int16.new(args[:arp_opcode] || 1),
			EthMac.new.read(args[:arp_src_mac] || "\x00\x01\xAC\x00\x00\x00"),
			Octets.new.read(args[:arp_src_ip] || "\x00\x00\x00\x00"),
			EthMac.new.read(args[:arp_dest_mac] || "\x00\x01\xAC\x00\x00\x00"),
			Octets.new.read(args[:arp_dest_ip] || "\x00\x00\x00\x00"),
			StructPf::StringPf.new.read(args[:body]))
	end

	#
	# Return the Object in from String , get All ARP Header
	#
	def to_s
		self.to_a.map {|x| x.to_s}.join
	end

	#
	# Read the ARP Header
	#
	def read str
		force_binary str
		return self if str.nil?
		self[:arp_hw].read str[0,2]
		self[:arp_proto].read str[2,2]
		self[:arp_hw_len].read str [4,1]
		self[:arp_proto_len].read str[5,1]
		self[:arp_opcode].read str[6,2]
		self[:arp_src_mac].read str[8,6]
		self[:arp_src_ip].read str[14,4]
		self[:arp_dest_mac].read str[18,6]
		self[:arp_dest_ip].read str[24,4]
		self[:body].read str[28, str.size]
		self
	end

	# Set arp Hardware type , Default 1 Ethernet
	def arp_hw= i; typecast "arp_hw", i; end
	# Get arp Hardware type
	def arp_hw; self[:arp_hw].to_i; end
	# Set arp Protocol type default 0x0800 
	def arp_proto= i; typecast "arp_proto", i; end
	# Get arp Protocol type
	def arp_proto; self[:arp_proto].to_i; end
	# Set arp Hardware size 
	def arp_hw_len= i; typecast "arp_hw_len", i; end
	# Get arp Hardware size
	def arp_hw_len; self[:arp_hw_len].to_i; end
	# Set arp Protocol size
	def arp_proto_len= i; typecast "arp_proto_len", i; end
	# Get arp Protocol size
	def arp_proto_len; self[:arp_proto_len].to_i; end
	# Set arp Opcode
	def arp_opcode= i; typecast "arp_opcode", i; end
	# Get arp Opcode
	def arp_opcode; self[:arp_opcode].to_i; end
	# Set arp Source MAC Address
	def arp_src_mac= i; typecast "arp_src_mac", i; end
	# Get arp Source MAC Address
	def arp_src_mac; self[:arp_src_mac].to_s; end
	# Set arp Source IP Address
	def arp_src_ip= i; typecast "arp_src_ip", i; end
	# Get arp Source IP Address
	def arp_src_ip; self[:arp_src_ip].to_s; end
	# Set arp Destination MAC Address
	def arp_dest_mac= i; typecast "arp_dest_mac", i; end
	# Get arp Destination MAC Address
	def arp_dest_mac; self[:arp_dest_mac].to_s; end
	# Set arp Destination IP Address
	def arp_dest_ip= i; typecast "arp_dest_ip", i; end
	# Get arp Destination IP Address
	def arp_dest_ip; self[:arp_dest_ip].to_s; end

	# Set the readable about arp_src_mac
	def arp_saddr_mac= mac
		mac = EthHeader.mac2str(mac)
		self[:arp_src_mac].read(mac)
		self.arp_src_mac
	end

	# Get the readable about arp_src_mac
	def arp_saddr_mac
		EthHeader.str2mac(self[:arp_src_mac].to_s)
	end

	# Set the readable about arp_src_ip
	def arp_saddr_ip= ip
		self[:arp_src_ip].read_quad(ip)
	end

	# Get the readable about arp_src_ip
	def arp_saddr_ip
		self[:arp_src_ip].to_x
	end

	# Set the readable about arp_dest_mac
	def arp_daddr_mac= mac
		mac = EthHeader.mac2str(mac)
		self[:arp_dest_mac].read(mac)
		self.arp_dest_mac
	end

	# Get the readable about arp_dest_mac
	def arp_daddr_mac
		EthHeader.str2mac(self[:arp_dest_mac].to_s)
	end

	# Set the readable about arp_dest_ip
	def arp_daddr_ip= ip
		self[:arp_dest_ip].read_quad(ip)
	end

	# Get the readable about arp_dest_ip
	def arp_daddr_ip
		self[:arp_dest_ip].to_x
	end

	alias :arp_src_mac_readable  :arp_saddr_mac 
	alias :arp_src_ip_readable   :arp_saddr_ip  
	alias :arp_dest_mac_readable :arp_daddr_mac 
	alias :arp_dest_ip_readable :arp_daddr_ip  

	# Get the readable protocol type
	def arp_proto_readable
		"0x%04x" % arp_proto
	end
end #class ARPHeader

require_relative "./packet.rb"
class ARPPacket < PacketPf
	attr_accessor :eth_header, :arp_header

	def self.can_parse? str
		return false unless EthPacket.can_parse? str
		return false unless str.size >= 42
		return false unless str[12,2] == "\x08\x06"
		true
	end

	def read(str=nil, args={})
		super
		raise "Can't Parse" unless ARPPacket.can_parse? str
		@eth_header.read(str)
		@arp_header.read(str[14, str.size])
		@eth_header.body = @arp_header
		self
	end

	def initialize(args={})
		@eth_header = EthHeader.new(args).read(args[:eth])
		@arp_header = ARPHeader.new(args).read(args[:arp])
		@eth_header.eth_proto = "\x08\x06"
		@eth_header.body = @arp_header

		case (args[:flover].nil?) ? :nil : args[:flover].to_s.downcase.to_sym
			when :windows
				@arp_header.body = "\x00" * 64
			when :linux
				@arp_header.body = "\x00" * 4 +
					"\x00\x07\x5c\x14" + "\x00" * 4 +
					"\x00\x0f\x83\x34" + "\x00\x0f\x83\x74" +
					"\x01\x11\x83\x78" + "\x00\x00\x00\x0c" +
					"\x00\x00\x00\x00"
				# total 32 byte with linux flag
			else
				@arp_header.body = "\x00" * 18
		end

		@headers = [@eth_header, @arp_header]
		super
	end

	def peek_fromt
		peek = ["A   "]
		peek << "%-5d" % self.to_s.size
		peek << arp_saddr_mac
		peek << "(#{arp_saddr_ip})"
		peek << " -> "
		peek << case arp_daddr_mac
			when "00:00:00:00:00:00"; "Bcast00"
			when "FF:FF:FF:FF:FF:FF"; "BcastFF"
			else; arp_saddr_mac; end
		peek << "(#{arp_daddr_ip})"
		peek << " : "
		peek << case arp_opcode
			when 1; "Requ"
			when 2; "Repl"
			when 3; "RReq"
			when 4; "RRpl"
			when 5; "IReq"
			when 6; "IRpl"
			else; "0x%02x" % arp_opcode; end
		peek.join
	end

end 	#class ARPPacket
