module Sub_Program

class ARP

	def initialize(*args)
		@send = Conn::Send.new
		@send.set_def_arp
		@send.cmd(*args)
	end

	attr_accessor :send

	def inject
		@send.inject
	end

end	# class ARP
end	# module Sub_Program
