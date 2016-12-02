require_relative "../core.rb"
require_relative "../ping.rb"

ping = Ping.new
ping.cmd_ping($!)
