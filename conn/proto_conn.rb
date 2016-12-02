module Conn
module Proto

        #
        # Create a ICMP Packet and register the CMD
        #
        def create_icmp
                self.register(ICMPPacket.new)
        end

        #
        # Create a ARP Packet and register the CMD
        #
        def create_arp
                self.register(ARPPacket.new)
        end

	#
	# Create a ARP Packet and get the Default ARP Packet value
	#
        def set_def_arp
                my_mac = Socket.getmyhostmac
                create_arp
                self.packet.eth_src = my_mac
                self.packet.eth_dest = "FF:FF:FF:FF:FF:FF"
                self.packet.arp_opcode = 1 
                self.packet.arp_src_mac = my_mac
                self.packet.arp_src_ip = Socket.getmyhostip.to_s
                self.packet.arp_dest_mac = "00:00:00:00:00:00"
                self
        end 

	#
	# Create a ICMP Packet and get the Default ICMP Packet value
	#
        def set_def_icmp
                create_icmp
                self.packet.eth_src = Socket.getmyhostmac
                self.packet.ip_src = Socket.getmyhostip
                self.packet.icmp_type = 8 
                self.packet.icmp_code = 0 
                self.packet.icmp_id = 1 
                self.packet.recalc
                self
        end

	#
	# This method is used to select which appropriate 
	# Return the Packet Read Class
	#
	def read_proto(pkt)
		proto = PacketPf.parse(pkt)
		if PacketPf.packet_prefixes.include?(proto)
			return Object::const_get("#{proto.upcase}Packet").new.read(pkt) rescue  $stderr.puts "Havn't the Protocol to read"
		end
	end

=begin
	#
	# Read with ARPPacket
	#
	def read_arp(packet)
		ARPPacket.new.read(packet)
	end

	#
	# Read with ICMPPacket
	#
	def read_icmp(packet)
		ICMPPacket.new.read(packet)
	end
=end
end	#module Proto
end	#module Conn
