module Parser
#
# Use to Register the Arguments
#
class Register
	
	def initialize
	end

	def eth_register
		fmt = {}
		fmt['--eth-src']   = [true, "Ethernet-II source MAC Address"]
		fmt['--eth-dest']  = [true, "Ethernet-II destination MAC Address"]
		fmt['--eth-proto'] = [true, "Ethernet-II next protocol frag"]
		fmt
	end

	def ip_register
		fmt = {}
		fmt['--ip-v']   = [true, "IP Version"]
		fmt['--ip-hl']  = [true, "IP Header Length"]
		fmt['--ip-tos'] = [true, "IP TOS"]
		fmt['--ip-len'] = [true, "IP Packet Total Length"]
		fmt['--ip-frag']= [true, "IP Frag"]
		fmt['--ip-ttl'] = [true, "IP TTL"]
		fmt['--ip-proto'] = [true, "IP next protocol frag"]
		fmt['--ip-badsum'] = [false, "Set a bad ckecksum to IP Sum"]
		fmt['--ip-src'] = [true, "IP source Address"]
		fmt
	end

	def icmp_register
		fmt = {}
		fmt["--icmp-type"] = [true, "icmp type"]
		fmt["--icmp-code"] = [true, "icmp code"]
		fmt
	end

	def arp_register
		fmt = {}
		fmt["--arp-hw"] = [true, "ARP Hardware"]
		fmt["--arp-proto"] = [true, "ARP Protocol"]
		fmt["--arp-hw-len"] = [true, "ARP Hardware Length"]
		fmt["--arp-proto-len"] = [true, "ARP Protocol Length"]
		fmt["--arp-opcode"] = [true, "ARP Opcode"]
		fmt["--arp-src-mac"] = [true, "ARP Source MAC Address"]
		fmt["--arp-src-ip"] = [true, "ARP Source IP Address"]
		fmt["--arp-dest-mac"] = [true, "ARP Destination MAC Address"]
		fmt["--arp-dest-ip"] = [true, "ARP Destination IP Address"]
		fmt
	end


	def def_register
		fmt = {}
		fmt['-h'] 	 = [false, "You looks like a baby :)"]
		fmt['--payload'] = [true, "Payload Someting"]
		fmt
	end

	#
	# Return the Given Packet Register
	#
	def inject(hdr)
		register = {}
		hdr.headers.each { |h|
			# reg => eth ; ip; icmp; arp
			reg = h.class.to_s.match(/(.*)Header/)[1].downcase	
			reg = reg << "_register"
			register.merge!(self.send(reg.to_sym))
		}
		register.merge!(self.def_register)
		return register
	end

end     # class Register

end     # Module Perser

