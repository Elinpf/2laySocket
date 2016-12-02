load "internal_raw.rb"

icmp = TestSocket2.new 
icmp.setup
p icmp.test_ping
