class C
	attr_accessor :a, :b, :c
	def initialize
		@a = A.new.read("a")
		@b = "b"
		@c = [@a, @b]
	end

	def pc
		@c
	end

	def b= str
		@b = str
	end
end	   

class A
	attr_accessor :a	
	def read str
		self.a = str
		self
	end
end
