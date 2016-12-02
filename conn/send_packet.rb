require_relative "../core"

module Conn

# @send = Conn::Send.new
# @send.set_def_arp
# @send.inject
class Send < Conn

	def initialize(args={})
		super
	end

	def inject
		@sock.send(@packet.to_s, 0)
		$stdout.puts @packet.peek_fromt
	end

	#
	# Use Init the packet, and send the packet with cmd
	#
	def cmd(*cmd_args)
		setup_opts = {}
		begin
			@arguments.parser(*cmd_args) do |opt,idx,val|
				if opt == '-h'
					@arguments.usage
					Kernel.exit(1)
				end
				@packet.each_header do |type|
					type << "_case"
					setup_opts.merge!(Parser::Case.new.send(type.to_sym,opt,val))
				end
			end
		rescue
			@arguments.usage
			Kernel.exit(1)
		end
		self.setup(setup_opts)
	end


		
end 	#class Send
end	#moduel Conn
