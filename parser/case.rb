module Parser
#
# Use to switch arguments
# $ip_dest
#
class Case
	def eth_case(opt, val)
		setup_opt = {}
		case opt
			when '--eth-src'
				setup_opt[:eth_src] = val
			when '--eth-dest'
				setup_opt[:eth_dest] = val
			when '--eth-proto'
				setup_opt[:eth_proto] = val.to_i
		end
		return setup_opt
	end

	def ip_case(opt, val)
		setup_opt = {}
		case opt
			when '--ip-v'
				setup_opt[:ip_v] = val.to_i
			when '--ip-hl'
				setup_opt[:ip_hl] = val.to_i
			when '--ip-tos'
				setup_opt[:ip_tos] = val.to_i
			when '--ip-len'
				setup_opt[:ip_len] = val.to_i
			when '--ip-id'
				setup_opt[:ip_id] = val.to_i
			when '--ip-frag'
				setup_opt[:ip_frag] = val.to_i
			when '--ip-ttl'
				setup_opt[:ip_ttl] = val.to_i
			when '--ip-proto'
				setup_opt[:ip_proto] = val.to_i
			when '--ip-badsum'
				setup_opt[:ip_sum] = false
			when '--ip-src'
				setup_opt[:ip_src] = val
			when nil 
				setup_opt[:ip_dest] = val
				$ip_dest = val
			when '--ip-dest'
				setup_opt[:ip_dest] = val
				$ip_dest = val
		end
		return setup_opt
	end

	def icmp_case(opt, val)
		setup_opt = {}
	       	case opt
			when "--icmp-type"
				setup_opt[:icmp_type] = val.to_i
			when "--icmp-code"
				setup_opt[:icmp_code] = val.to_i
			when "--icmp-badsum"
				setup_opt[:icmp_sum] = false
		end
		return setup_opt
	end

	def arp_case(opt, val)
		setup_opt = {}
		case opt
			when "--arp-hw"
				setup_opt[:arp_hw] = val.to_i
			when "--arp-proto"
				setup_opt[:arp_proto] = val.to_i
			when "--arp-hw-len"
				setup_opt[:arp_hw_len] = val.to_i
			when "--arp-proto-len"
				setup_opt[:arp_proto_len] = val.to_i
			when "--arp-opcode"
				setup_opt[:arp_opcode] = val.to_i
			when "--arp-src-mac"
				setup_opt[:arp_src_mac] = val
			when "--arp-src-ip"
				setup_opt[:arp_src_ip] = val
			when "--arp-dest-mac"
				setup_opt[:arp_dest_mac] = val
			when "--arp-dest-ip"
				setup_opt[:arp_dest_ip] = val
			when nil
				setup_opt[:arp_dest_ip] = val
		end
		return setup_opt
	end

	def def_case(opt, val)
		setup_opt = {}
		case opt
			when '--payload'
				setup_opt[:payload] = val
		end
		return setup_opt
	end
		

end 	#Module Case

end	#Moduel Parser
