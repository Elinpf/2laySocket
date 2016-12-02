module StructPf

#
#:v = value :d = default
#

#
#make sure the type is struct
#
def typecast call, i
	self[call.to_sym].read i
end

#	
#make sure the String type is struct
#
def body= str
	if str.kind_of? ::String
		typecast "body", force_binary(str)
	elsif str.kind_of? StructPf
		self[:body] = str
	elsif str.nil?
		StructPf::StringPf.new.read("")
	else
		raise ArgumentError "Can't cram a #{str} to Struct String body"
	end
end

#
#Return the encode to binary
#The dup is use when str is ARGV given frozen flag
#
def force_binary str
	StructPf.force_binary str
end

def self.force_binary str
	str.dup.force_encoding "binary" if str.respond_to? :force_encoding	
end

#
#Struct ( :value , :default)
#
class Int < Struct.new(:v, :d)

	def initialize(v=nil, d=nil)
		super(v, d=0)
	end

	#cast to string , interface
	def to_s
		raise StandardError, "StructFu::Int#to_s accessed, must be redefined"
	end
	
	#cast to interage
	def to_i
		(self.v || self.d).to_i
	end

	#cast the integer struct
	def read i
		self.v = i.kind_of?(Integer) ? i.to_i : i.to_s.unpack(@packstr).first

		self
	end
end

class Int8 < Int
	
	def initialize(v=nil, d=nil)
		super(v,d)
		@packstr = "C"
	end

	#return 8-bit interage string
	def to_s
		[self.v].pack("C")
	end
end

class Int16 < Int
	
	def initialize(v=nil, d=nil)
		super(v,d)
		@packstr = "n"
	end

	#return 16-bit interage string
	def to_s
		[self.v].pack("n")
	end
end

class Int32 < Int
	
	def initialize(v=nil, d=nil)
		super(v,d)
		@packstr = "N"
	end

	#return 32-bit big interage string
	def to_s
		[self.v].pack("N")
	end
end

class StringPf < ::String
	#return StringPf class given body=	
	def read str
		str = str.to_s
		self.replace(str)
		self
	end
end
end

