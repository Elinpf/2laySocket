load "core.rb"
load "conn/conn.rb"
load "conn/send_packet.rb"

Thread.new do 
	Conn::Capture.new.run.show_live
end
arp = Conn::Send.new.set_def_arp 
if arp.cmd(ARGV)
	arp.inject
end

sleep 10
