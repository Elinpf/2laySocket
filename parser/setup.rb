module Parser
module Setup
def setup(opts)
	return self if opts.empty?

	#self.is_eth?
	if self.include?(EthHeader)
		self.eth_src = opts[:eth_src] if opts[:eth_src]
		self.eth_dest = opts[:eth_dest] if opts[:eth_dest]
		self.eth_proto = opts[:eth_proto] if opts[:eth_proto]
	end

	#self.is_ipv4?
	if self.include?(IPHeader)
		self.ip_v = opts[:ip_v] if opts[:ip_v]
		self.ip_hl = opts[:ip_hl] if opts[:ip_hl]
		self.ip_tos = opts[:ip_tos] if opts[:ip_tos]
		self.ip_len = opts[:ip_len] if opts[:ip_len]
		self.ip_id = opts[:ip_id] if opts[:ip_id]
		self.ip_frag = opts[:ip_frag] if opts[:ip_frag]
		self.ip_ttl = opts[:ip_ttl] if opts[:ip_ttl]
		self.ip_proto = opts[:ip_proto] if opts[:ip_proto]
		(opts[:ip_sum] == false) ? self.ip_sum = rand(2**16) : self.recalc(:ip)
		self.ip_src = opts[:ip_src] if opts[:ip_src]
		self.ip_dest = opts[:ip_dest] if opts[:ip_dest]
	end

	#self.is_icmp?
	if self.include?(ICMPHeader)
                self.icmp_type = opts[:icmp_type] if opts[:icmp_type]
                self.icmp_code = opts[:icmp_code] if opts[:icmp_code]
                (opts[:icmp_sum] == false) ? self.icmp_sum = rand(2**16) : self.recalc(:icmp)
                self.icmp_id = opts[:icmp_id] if opts[:icmp_id]
                self.icmp_id = opts[:icmp_seq] if opts[:icmp_seq]
                self.payload = opts[:payload] if opts[:payload]
	end

	#self.is_arp?
	if self.include?(ARPHeader)
		self.arp_hw = opts[:arp_hw] if opts[:arp_hw]
		self.arp_proto = opts[:arp_proto] if opts[:arp_proto]
		self.arp_hw_len = opts[:arp_hw_len] if opts[:arp_hw_len]
		self.arp_proto_len = opts[:arp_proto_len] if opts[:arp_proto_len]
		self.arp_opcode = opts[:arp_opcode] if opts[:arp_opcode]
		self.arp_src_mac = opts[:arp_src_mac] if opts[:arp_src_mac]
		self.arp_src_ip = opts[:arp_src_ip] if opts[:arp_src_ip]
		self.arp_dest_mac = opts[:arp_dest_mac] if opts[:arp_dest_mac]
		self.arp_dest_ip = opts[:arp_dest_ip] if opts[:arp_dest_ip]
	end
	#recalc all has a probrom is if ip-badsum or icmp-badsum, this will recalc
	#(opts[:recalc] == false) ? self.ip_sum = rand(2**16) : self.recalc
	#default
	self.payload = opts[:payload] if opts[:payload]
	self
end
end
end
