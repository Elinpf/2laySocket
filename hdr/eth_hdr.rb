require_relative "../core.rb"

#The Eth2 Protocol use in EthHeader
module ETH_PROTO
	ETH_PROTO_ARP 	= 0x0806
	ETH_PROTO_IP	= 0x0800
	ETH_PROTO_RARP  = 0x0835
	ETH_PROTO_ALL   = 0x0003
end


# EthOui is the Organizationally Unique Identifier portion of a MAC address
# used in EthHeader.
# ==== Header Definition
#
#  Fixnum   :b0
#  Fixnum   :b1
#  Fixnum   :b2
#  Fixnum   :b3
#  Fixnum   :b4
#  Fixnum   :b5
#  Fixnum   :local
#  Fixnum   :multicast
#  Int16    :oui,       Default: 0x1ac5 :)
class EthOui < Struct.new(:b5, :b4, :b3, :b2, :b1, :b0, :local, :multicast, :nic)

	include StructPf

	def initialize(args={})
		args[:local] ||= 0
		args[:nic] ||= 0x1ac
		args.each_pair {|k,v| args[k] = 0 unless v}
		super(
			args[:b5] || 0, args[:b4] || 0, args[:b3] || 0,
			args[:b2] || 0,	args[:b1] || 0, args[:b0] || 0,
			args[:local], args[:multicast] || 0,
			args[:nic])
	end

	#Return after pack 
	def to_s
		byte  = 0
		byte += 0b10000000 if b5.to_i == 1
		byte += 0b01000000 if b4.to_i == 1
		byte += 0b00100000 if b3.to_i == 1
		byte += 0b00010000 if b2.to_i == 1
		byte += 0b00001000 if b1.to_i == 1
		byte += 0b00000100 if b0.to_i == 1
		byte += 0b00000010 if local.to_i == 1
		byte += 0b00000001 if multicast.to_i == 1
		[byte, nic].pack("Cn")
	end

	#Read the Given String to Object
	def read str
		#str.force_encoding "binary" if str.respond_to? :force_encoding
		force_binary str
		return self if str.nil?
		if 1.respond_to? :ord
			byte = str[0].ord
		else
			byte = str[0]
		end

		self[:b5] = byte & 0b10000000 == 0b10000000 ? 1 : 0
		self[:b4] = byte & 0b01000000 == 0b01000000 ? 1 : 0
		self[:b3] = byte & 0b00100000 == 0b00100000 ? 1 : 0
		self[:b2] = byte & 0b00010000 == 0b00010000 ? 1 : 0
		self[:b1] = byte & 0b00001000 == 0b00001000 ? 1 : 0
		self[:b0] = byte & 0b00000100 == 0b00000100 ? 1 : 0
		self[:local]	 = byte & 0b00000010 == 0b00000010 ? 1 : 0
		self[:multicast] = byte & 0b00000001 == 0b00000001 ? 1 : 0
		self[:nic] = str[1,2].unpack("n").first
		self
	end
end 	#class EthOui

#Class Mac Network Interface Card 
# EthNic is the Network Interface Controler portion of a MAC address, used in EthHeader.
#
# ==== Header Definition
#
#  Fixnum :n1
#  Fixnum :n2
#  Fixnum :n3
#
class EthNic < Struct.new(:n1, :n2, :n3)

	include StructPf

	def initialize(args={})
		args.each_pair {|k,v| args[k] = 0 unless v}
		super( args[:n1] || 0, args[:n2] || 0, args[:n3] || 0 )
	end

	def to_s
		[n1, n2, n3].map {|x| x.to_i}.pack("C3")
	end

	def read str
		#str.force_encoding "binary" if str.respond_to? :force_encoding
		force_binary str
		return self if str.nil?
		self[:n1], self[:n2], self[:n3] = str[0,3].unpack("C3")
		self
	end

end 	#class EthNic


class EthMac < Struct.new(:oui, :nic)

	include StructPf

	def initialize(args={})
		super(
		     	EthOui.new.read(args[:oui]),
			EthNic.new.read(args[:nic]))
	end

	def to_s
		"#{self[:oui]}#{self[:nic]}"
	end

	def read str
		#str.force_encoding "binary" if str.respond_to? :force_encoding
		force_binary str
		return self if str.nil?
		if str =~ /([0-9a-fA-F][0-9a-fA-F]:)+/
			str = EthHeader.mac2str(str)
		end
		self[:oui] = EthOui.new.read str[0,3]
		self[:nic] = EthNic.new.read str[3,3]
		self
	end

end	#class EthMac

class EthHeader < Struct.new(:eth_dest, :eth_src, :eth_proto, :body)

	include StructPf

	def initialize(args={})
		super(
			EthMac.new.read(args[:eth_dest]  || "\x00\x01\xAC\x00\x00\x00"),
			EthMac.new.read(args[:eth_src] || "\x00\x01\xAC\x00\x00\x00"),
			Int16.new(args[:eth_proto] || 0x0800),
			StructPf::StringPf.new.read(args[:body] || ""))
	end

	#Return the String from EthHeader
	def to_s
		self.to_a.map {|x| x.to_s}.join
	end	

	#Read the String to EhtHeader
	def read str
		#str.force_encoding "binary" if str.respond_to? :force_encoding
		force_binary str
		return self if str.nil?
		self[:eth_dest]	 = EthMac.new.read str[0,6]
		self[:eth_src]  = EthMac.new.read str[6,6]
		self[:eth_proto] = Int16.new.read  str[12,2]
		self[:body]  	 = StructPf::StringPf.new.read str[14,str.size]
		self
	end

	#
	#Set/Get Ethernet Sorece Mac Address
	#
	def eth_src= i
		typecast "eth_src", i
	end

	def eth_src
		self[:eth_src].to_s
	end

	#
	#Set/Get Ethernet Destination Mac Address
	#
	def eth_dest= i
		typecast "eth_dest", i
	end

	def eth_dest
		self[:eth_dest].to_s
	end

	#
	#Set/Get Ethernet Protocol
	#
	def eth_proto= i
		typecast "eth_proto", i
	end

	def eth_proto
		self[:eth_proto].to_i
	end

	#The Mac To String like "90:00:4e:5e:f1:ef"  =>  "\x90\x00N^\xF1\xEF"
	def self.mac2str mac
		if mac.split(/[:\x2d\x2e\x5f]+/).size == 6
			res = mac.split(/[:\x2d\x2e\x20\x5f]+/).collect {|x| x.to_i(16)}.pack("C6")
		else
			raise ArgumentError, "Unknow format for mac address."
		end
		return res
	end

	#The String to Mac like "\x90\x00N^\xF1\xEF" =>  "90:00:4e:5e:f1:ef"
	def self.str2mac str=''
		if str.to_s.size == 6 && str.kind_of?(::String)
			res = str.unpack("C6").collect {|x| sprintf("%02x",x)}.join(':')
		end
		return res
	end

	#Set/Get the format for Mac to Ethernet Source Address
	def eth_saddr= mac
		mac = EthHeader.mac2str mac
		self[:eth_src].read mac
		self
	end
	
	def eth_saddr
		EthHeader.str2mac(self[:eth_src].to_s)
	end

	#Set/Get format for Mac to Ethernet Destination Address
	def eth_daddr= mac
		mac = EthHeader.mac2str mac
		self[:eth_dest].read mac
		self
	end

	def eth_daddr
		EthHeader.str2mac(self[:eth_dest].to_s)
	end

	alias :eth_src_readable  :eth_saddr
	alias :eth_dest_readable :eth_daddr

	#Return the reable format Ethernet Protocol
	def eth_proto_readable
		"0x%04x" % eth_proto
	end
end 	#class EthHeader

require_relative "./packet.rb"
class EthPacket < PacketPf
	attr_accessor :eth_header

	#Return true if the EthHeader include IP, ARP Protocol flag
	#Overraid the SuperClass self.can_parse?
	def self.can_parse? str
		#0x0800 => IP, 0x0806 => ARP, 0x08dd => ?
		valid_eth_types = [0x0800, 0x0806, 0x08dd]

		return false unless str.size >= 14
		type = str[12,2].unpack("n").first rescue nil
		return false unless valid_eth_types.include? type
		true
	end

	def read (str=nil, args={})
		raise "Can't parse" unless EthPacket.can_parse? str
		@eth_header.read str
		super
		return self
	end

	def initialize(args={})
		@eth_header = EthHeader.new(args).read(args[:eth])
		@headers = [@eth_header]
		super
	end

end 	#class EthPacket

