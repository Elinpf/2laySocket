# IPHeader is a complete IP struct, used in IPPacket. Most traffic on most networks     today is IP-based.
#
# For more on IP packets, see http://www.networksorcery.com/enp/protocol/ip.htm
#
# ==== Header Definition
#
#   Fixnum (4 bits)  :ip_v,     Default: 4
#   Fixnum (4 bits)  :ip_hl,    Default: 5
#   Int8             :ip_tos,   Default: 0           # TODO: Break out the bits
#   Int16            :ip_len,   Default: calculated 
#   Int16            :ip_id,    Default: calculated  # IRL, hardly random. 
#   Int16            :ip_frag,  Default: 0           # TODO: Break out the bits
#   Int8             :ip_ttl,   Default: 0xff        # Changes per flavor
#   Int8             :ip_proto, Default: 0x01        # TCP: 0x06, UDP 0x11, ICMP 0x0    1
#   Int16            :ip_sum,   Default: calculated 
#   Octets           :ip_src                       
#   Octets           :ip_dest                      
#   String           :body
#
# Note that IPPackets will always be somewhat incorrect upon initalization, 
# and want an IPHeader#recalc() to become correct before a 
# Packet#to_f or Packet#to_w.

require_relative "../core.rb"


#
#Use to mask the IPAddr to hex like "\xff"
#
class Octets < Struct.new(:o1, :o2, :o3, :o4)
	include StructPf

	def initialize(args={})
		super(	Int8.new(args[:o1]),
			Int8.new(args[:o2]),
			Int8.new(args[:o3]),
			Int8.new(args[:o4]))
	end

	#Return the object in String from.
	def to_s
		self.to_a.map {|x| x.to_s}
	end

	#Return the Object in Address link "192.168.0.1"
	def to_x
		str = self.to_a.map {|x| x.to_i.to_s}.join('.')
		IPAddr.new(str).to_s
	end

	#Return the object in Address of Number
	def to_i
		ip_addr = self.to_a.map {|x| x.to_i.to_s}.join('.')
		IPAddr.new(ip_addr).to_i
	end

	#Reads a String to populate the object.
	#The dup is use when str is ARGV given frozen flag
	def read str
		force_binary str
		return self if str.nil?
		if str =~ /((.*)\.)/
			str = [IPAddr.new(str).to_i].pack("N")
		end
		self[:o1].read str[0,1]
		self[:o2].read str[1,1]
		self[:o3].read str[2,1]
		self[:o4].read str[3,1]
		self
	end

	#Read the dotted-quad like "192.168.0.1"
	def read_quad str
		read([IPAddr.new(str).to_i].pack("N"))
	end
end

class IPHeader < Struct.new(	:ip_v, :ip_hl, :ip_tos, :ip_len,
				:ip_id, :ip_frag,
				:ip_ttl, :ip_proto, :ip_sum,
				:ip_src, :ip_dest, #:ip_opt,
				:body
			)
	include StructPf

	def initialize(args={})
		@random_id = rand(0xffff)
		super(
			(args[:ip_v] || 4),
			(args[:ip_hl] || 5),
			Int8.new(args[:ip_tos] || 0),
			Int16.new(args[:ip_len] || 0),
			Int16.new(args[:ip_id] || ip_calc_id),
			Int16.new(args[:ip_frag] || 0),
			Int8.new(args[:ip_ttl] || 0xff),
			Int8.new(args[:ip_proto] || 0x01),
			Int16.new(args[:ip_sum] || 0xffff),
			Octets.new.read(args[:ip_src] || "\x00\x00\x00\x00"),
			Octets.new.read(args[:ip_dest] || "\x00\x00\x00\x00"),
			#don't Have the IP Options 
			StructPf::StringPf.new.read(args[:body] || ""))
	end

	#set the ip_version if you must
	def ip_v= i
		self[:ip_v] = i.to_i
	end

	#get the ip_version
	def ip_v
		self[:ip_v].to_i
	end

	#set the ip_header_length if you must
	def ip_hl= i
		self[:ip_hl] = i.to_i
	end

	#get the ip_header_length 
	def ip_hl
		self[:ip_hl]
	end

	#set the ip_tos
	def ip_tos= i
		typecast "ip_tos", i	
	end

	#get the IP TOS
	def ip_tos
		self[:ip_tos].to_i
	end

	#set the IP Total Length if you must
	def ip_len= i
		typecast("ip_len", i)
	end

	#get the IP Total Length
	def ip_len
		self[:ip_len].to_i
	end

	#set the ip Identification if you must
	def ip_id= i
		typecast("ip_id", i)
	end

	#get the ip Identification 
	def ip_id
		self[:ip_id].to_i
	end

	#Return the Readable for dissect
	def ip_id_readable
		"0x%04x" % ip_id
	end

	#set the IP Fragment Offset if you must 
	def ip_frag= i
		typecast("ip_frag", i)
	end

	#get the IP Fragment Offset
	def ip_frag
		self[:ip_frag].to_i
	end

	#set the IP TTL
	def ip_ttl= i
		typecast("ip_ttl", i)
	end

	#get the IP TTL
	def ip_ttl
		self[:ip_ttl].to_i
	end

	#set the IP Protocol 
	def ip_proto= i
		typecast("ip_proto", i)
	end

	#get the IP Protocol
	def ip_proto
		self[:ip_proto].to_i
	end

	#Set the IP CheckSum Number if you must to be a bad Sum
	def ip_sum= i
		typecast("ip_sum", i)
	end

	#get the IP CheckSum Number
	def ip_sum
		self[:ip_sum].to_i
	end

	#Return the readable for dissect
	def ip_sum_readable
		"0x%04x" % ip_sum
	end

	#Set the IP Source Address
	def ip_src= i
		case i
			when Numeric
				#the i is Numeric use Pack("N")
				self[:ip_src] = Octets.new.read([i].pack("N"))
			when String
				#the i is String use unpack("C")
				if i =~ /\./
					self[:ip_src] = Octets.new.read(i.split('.').collect {|x| [x.to_i].pack("C")}.join)
				else
					self[:ip_src] = Octects.new.read(i.unpack("N"))
				end
			when Octets
				self[:ip_src] = i
			else
				typecast "ip_src", i
		end
		
	end
		
	#Get the IP Source
	def ip_src
		self[:ip_src].to_i
	end

	#Set the IP Destination Address
	def ip_dest= i
		case i
			when Numeric
				self[:ip_dest] = Octets.new.read([i].pack("N"))
			when String
				if i =~ /\./
					self[:ip_dest] = Octets.new.read(i.split('.').collect {|x| [x.to_i].pack("C")}.join)
				else
					self[:ip_dest] = Octets.new.read(i.unpack("N"))
				end
			when Octets
				self[:ip_dest] = i
			else
				typecast "ip_dest", i
		end
	end

	#Get the IP Destination Address
	def ip_dest
		self[:ip_dest].to_i		
	end

	#Using in dissect
	def ip_saddr= i
		self[:ip_src].read_quad i
	end

	def ip_saddr
		self[:ip_src].to_x
	end

	def ip_daddr= i
		self[:ip_dest].read_quad i
	end

	def ip_daddr
		self[:ip_dest].to_x
	end
	
	alias :ip_src_readable  :ip_saddr
	alias :ip_dest_readable :ip_daddr

	#Read a IP Header String to populate the Object
	def read str
		force_binary str if str.respond_to? :force_encoding
		return self if str.nil?
		self[:ip_v] 	= str[0,1].unpack("C").first >> 4
		self[:ip_hl]	= str[0,1].unpack("C").first & 0xf
		self[:ip_tos].read   str[1,1]
		self[:ip_len].read   str[2,2]
		self[:ip_id].read    str[4,2]
		self[:ip_frag].read  str[6,2]
		self[:ip_ttl].read   str[8,1]
		self[:ip_proto].read str[9,1]
		self[:ip_sum].read   str[10,2]
		self[:ip_src].read   str[12,4]
		self[:ip_dest].read  str[16,4]
		self[:body].read     str[20,str.size] if str.size > 20 
		self
	end 

	#Return the String of the IP Header 
	def to_s
		#Hex 
		ip_v_hl = [(self[:ip_v] << 4) + self[:ip_hl]].pack("C")
		ip_v_hl + self.to_a[2,10].map {|x| x.to_s}.join
	end

	#
	#Calc the IP Header CheckSum
	#Every 16bit add
	#
	def ip_calc_sum
		sum  = ((self.ip_v << 4) + self.ip_hl << 8) + self.ip_tos
		sum += self.ip_len
		sum += self.ip_id
		sum += self.ip_frag
		sum += (self.ip_ttl << 8) + self.ip_proto
		sum += self.ip_src >> 16
		sum += self.ip_src & 0xffff
		sum += self.ip_dest >> 16
		sum += self.ip_dest & 0xffff
		sum = sum % 0xffff
		sum = 0xffff - sum
		sum == 0 ? 0xffff : sum
	end

	#Return the init @random 
	def ip_calc_id
		@random_id
	end

	#Recalc the IPHeader Length
	def ip_calc_len
		(self.ip_hl * 4) + self.body.to_s.length
	end

	def ip_recalc(args=:all)
		case args
		when :ip_sum
			self.ip_sum = self.ip_calc_sum
		when :ip_id
			self.ip_id  = self.ip_calc_id
		when :ip_len
			self.ip_len = self.ip_calc_len
		when :all
			self.ip_sum = self.ip_calc_sum
			self.ip_id  = self.ip_calc_id
			self.ip_len = self.ip_calc_len
		else
			raise ArgumentError, "No such field #{args}"
		end
	end
end #class IPHeader


require_relative "./packet.rb"
class IPPacket < PacketPf

	attr_accessor :eth_header, :ip_header

	def self.can_parse? str
		return false unless str.size >= 34
		return false unless EthPacket.can_parse? str
		if str[12,2] == "\x08\x00"
			if 1.respond_to? :ord
				ipv = str[14,1][0].unpack("C").first >> 4
			else
				ipv = str[14,1][0].unpack("C").first >> 4
			end
			return false unless ipv == 4
			return true
		else
			false
		end
	end

	def read(str=nil, args={})
		raise "Can't parse" unless self.class.can_parse? str
		@eth_header.read str
		@ip_header.read str[14,str.size]
		@eth_header.body = @ip_header
		self.ip_recalc(:all) if args[:fix] || args[:recalc]
		self
	end

	def initialize(args={})
		@eth_header = EthHeader.new.read(args[:eth])
		@ip_header  = IPHeader.new.read(args[:ip])
		@eth_header.body = @ip_header
		
		@headers = [@eth_header, @ip_header]
		super
	end

	def peek_fromt
		peek = ["I   "]
		peek << "%-5d" % self.to_s.size
		peek << "%21s" % self.ip_saddr
		peek << "->"
		peek << "%-21s" % self.ip_daddr
		peek << "%-23s" % "I:"
		peek << "%04x" % self.ip_id
		peek.join
	end
end 	#class IPPacket	
