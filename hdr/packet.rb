
class PacketPf
	attr_reader   :flavor
	attr_accessor :headers
	attr_accessor :iface
	attr_accessor :inspect_style
	
	#Must be Override in the subclass 
	def self.can_parse? str
		false
	end

	def to_s
		@headers[0].to_s
	end

	
	def payload
		@headers.last.body
	end

	def payload= str
		@headers.last.body= str
	end

	#Read Can recalc the IP, ARP, ICMP and any other protocol checksum
	def read(str=nil,args={})
		StructPf.force_binary str
	end

	def recalc(args=:all)
		case args
		when :ip
			self.ip_recalc(:all)
		when :icmp
			self.icmp_recalc(:all)
		when :all
			self.ip_recalc(:all) if @ip_header
			self.icmp_recalc(:all) if @icmp_header
		else
			raise ArgumentError, "No such field, Try :all"
		end
		self
	end

	#
	#Make a Table Array [[proto, [1,2,3] ]
	#
	def dissection_table
		table = []
		@headers.each_with_index do |header, table_index|
			proto = header.class.name.sub(/^.*::/,"")
			table << [proto, []]
			header.members.each do |elem|
				elem_sym = elem.to_sym
				next if elem_sym == :body
				elem_type_table = []
				elem_type_table[0] = elem_sym
				readable_elem = "#{elem_sym}_readable"
				if header.respond_to? readable_elem
					elem_type_table[1] = header.send(readable_elem)
				else
					elem_type_table[1] = header.send(elem_sym)
				end
				elem_type_table[2] = header[elem_sym].class.name
				table[table_index][1] << elem_type_table
         		end
		end

	  if @headers.last.members.map {|x| x.to_sym}.include?(:body) && !self.payload.empty?
			body_part = [:body, self.payload, @headers.last.body.class.name]
		  	table << body_part
         	end
       	table
 	end

	#
	#Make The Table
	#
	def dissect
		dtable = self.dissection_table
		hex_body = nil
		if dtable.last.kind_of?(Array) && dtable.last.first == :body
			body = dtable.pop
			hex_body = hexify(body[1])
		end
		elem_width = [0,0,0]
		dtable.each do |elem_proto|
			elem_proto[1].each do |elem|
				elem.each_with_index do |e,i|
					width = e.size
					elem_width[i] = width if width > elem_width[i]
				end
			end
		end
		total_width = elem_width.inject(0) {|sum, x| sum + x}
		table = ""
		dtable.each do |elem_proto|
			table << "--"
			table << elem_proto.first
			if total_width > elem_proto.size
				table << "-" * (total_width - elem_proto.first.size + 2)
			else
				table << "-" * (total_width + 2)
			end 
			table << "\n"
			elem_proto[1].each do |elem|
				elem_table = []
				table << "  "
				3.times {|i| elem_table << ("%-#{elem_width[i]}s" % elem[i])}
				table << elem_table.join("\s")
				table << "\n"
			end 
		end 
		if hex_body && !hex_body.empty?	
			table << "-" * 66
			table << "\n"
			table << "00-01-02-03-04-05-06-07-08-09-0a-0b-0c-0d-0e-0f---0123456789abcdef\n"
			table << "-" * 66
			table << "\n"
			table << hex_body
		end
		table
	end

	def hexify str
		str.force_encoding "ASCII-8BIT" if str.respond_to? :force_encoding
		ascii_lines = str.to_s.unpack("H*")[0].scan(/.{1,32}/)
		reg = Regexp.new('[\x00-\x1f\x7f-\xff]', nil, 'n')
		char_lines = str.gsub(reg, '.').scan(/.{1,16}/)
		ret = []
		ascii_lines.size.times {|x| ret << "%-48s  %s" % [ascii_lines[x].scan(/.{1,2}/).join(' '), char_lines[x]]}
		ret.join("\n")
	end

	#
	#In the end of the class running
	#In fact the method is Object#p 
	#Must be called this method to overrid Object#inspect
	#
	def inspect
		self.dissect
	end

	def initialize(args={})
		if self.class.name =~ /(^|::)PacketFu::Packet$/
			raise NoMethodError, "Method `new' called for absrtact class #{self.class.name}"
		end
		
		if args[:config]
			args[:config].each_pair do |k,v|
				case k
				when :eth_daddr; @eth_header.eth_daddr= v if @eth_header
				when :eth_saddr; @eth_header.eth_saddr= v if @eth_header
				when :ip_saddr ; @ip_header.ip_saddr= v   if @ip_header
				when :iface    ; @iface = v
				end
			end
		end
	end

	#
	#Use in the other header to set and get information
	#
	def method_missing(sym, *args, &block)
		case sym.to_s
		when /([0-9a-zA-Z]+)_.+/
			ptype = $1
			if PacketPf.packet_prefixes.index(ptype)
				self.instance_variable_get("@#{ptype}_header").send(sym, *args, &block)
			else
				super
			end
		else
			super
		end
	end

	def self.packet_prefixes
		["eth", "ip", "arp", "icmp"]
	end

	# Return the Array like [EthPacket, IPPacket, ARPPacket, ICMPPacket]
	def self.packet_classes
		PacketPf.packet_prefixes.map {|ppre|
			if ppre =~ /eth/
				::Object.const_get("EthPacket")
			else
				::Object.const_get("#{ppre.upcase}Packet")
			end
		}
		
	end

	#
	# Return the class is what layer, and help for <=>
	#
	def self.layer
		case self.to_s
		when /EthPacket$/; 1
		when /IPPacket$/, /IPv6Packet$/, /ARPPacket$/; 2
		when /ICMPPacket$/, /TCPPacket$/, /UDPPacket$/; 3
		when /HSRPPacket$/; 4
		else self.new.headers.size
		end
	end

	def layer
		self.class.layer
	end

	# The include is tell like "EthHeader"
	def include? hdr
		@headers.map {|h| h.class}.include?(hdr)
	end

	def each_header(&block)
		arr_hdr = @headers.map {|h| h.class.to_s.match(/(.*)Header/)[1].downcase!}
		arr_hdr.each {|a| yield a}
	end
	
	def self.parse!(pkt)
		StructPf.force_binary(pkt)
		# Select the can parse Packet and Get the high layer to create and read.
		classes = PacketPf.packet_classes.select {|pclass| pclass.can_parse? pkt}
		p = classes.sort {|x,y| x.layer <=> y.layer}.last.new
		p.read(pkt)
	end
	
end	#class PacketPf
