module Parser
# Parser the CMD arguments
class Arguments
	def initialize(fmt)
		self.fmt = fmt
	end

	def parser(*args, &block)
		skip_next = false
		
		if args.size == 1 and args[0].kind_of? Array
			args = args[0]
		end

		args.each_with_index do |arg, idx|
			if skip_next == true
				skip_next = false
				next
			end
			
			if arg =~ /^-/
				cfs = arg[0..20]
				
				fmt.each_pair do |fmtspec, val|
					next if cfs != fmtspec

					param = nil

					if val[0]
						param = args[idx+1].dup
						skip_next = true
					end

					yield fmtspec, idx, param
				end
			else
				yield nil, idx, arg
			end
		end
	end

	def usage
		table = ""
		table << "-" * 60
		table << "\npping Version: #{Version::Ver}\n"
		table << "-" * 60
		table << "\nUsage:  pping [Options] <target>\n"

		self.fmt.each_pair do |opt, elem|
			table << "   %-20s%-20s: %-30s\n" % [opt, (elem[0] == true) ? " <opt>" : "", elem[1]]
		end
		puts table
	end
			

	attr_accessor :fmt
end

end	# Module Perser
