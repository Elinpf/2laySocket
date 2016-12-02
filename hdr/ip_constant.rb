##
#
#This module is IP Header Constant
#
##
module IP_CST


#
#IP Header Version and maxpacket
#
IP_VERSION		= 4
IP_MAXPACKET		= 65535

#
#Definitions IP Next Protocol 
#
IP_PROTO_TCP 		= 0x06
IP_PROTO_UDP 		= 0x11
IP_PROTO_ICMP 		= 0x01

#
#Definitions for Explicit Congestion Notification (ECN)
#
IPTOS_ECN_MASK		= 0x03
IPTOS_ECN_NOT_ECT	= 0x00
IPTOS_ECN_ECT1		= 0x01
IPTOS_ECN_ECT0		= 0x02
IPTOS_ECN_CE		= 0x03

#
#Definitions for IP differentiated services code points (DSCP)
#
IPTOS_DSCP_MASK		= 0xfc
IPTOS_DSCP_AF11		= 0x28
IPTOS_DSCP_AF12 	= 0x30
IPTOS_DSCP_AF13 	= 0x38
IPTOS_DSCP_AF21 	= 0x48
IPTOS_DSCP_AF22		= 0x50
IPTOS_DSCP_AF23		= 0x58
IPTOS_DSCP_AF31 	= 0x68
IPTOS_DSCP_AF32 	= 0x70
IPTOS_DSCP_AF33 	= 0x78
IPTOS_DSCP_AF41 	= 0x88
IPTOS_DSCP_AF42 	= 0x90
IPTOS_DSCP_AF43 	= 0x98
IPTOS_DSCP_EF		= 0xb8

#
#Definitions for IP type of service (ip tos)
#
IPTOS_TOS_MASK		= 0x1e
IPTOS_LOWDELAY 		= 0x10
IPTOS_THROUGHPUT  	= 0x08
IPTOS_RELIABILITY 	= 0x04
IPTOS_LOWCOST		= 0x02
IPTOS_MINCOST		= IPTOS_LOWCOST

#
#Definitions for IP precedence (also in ip_tos) (hopefully unused)
#
IPTOS_PREC_MASK			= 0xe0
IPTOS_PREC_NETCONTROL		= 0xe0  #Net control
IPTOS_PREC_INTERNETCONTROL  	= 0xc0
IPTOS_PREC_CRITIC_ECP		= 0xa0
IPTOS_PREC_FLASHOVERRIDE	= 0x80
IPTOS_PREC_FLASH		= 0x60
IPTOS_PREC_IMMEDIATE		= 0x40
IPTOS_PREC_PRIORITY		= 0x20
IPTOS_PREC_ROUTINE		= 0x00

#
#Definitions for options 
#
IPOPT_COPY		= 0x80
IPOPT_CLASS_MASK	= 0x60
IPOPT_NUMBER_MASK	= 0x1f

IPOPT_CONTROL		= 0x00
IPOPT_RESERVED1		= 0x20
IPOPT_DEBMEAS		= 0x40
IPOPT_MEASUREMENT	= IPOPT_DEBMEAS
IPOPT_RESERVED2		= 0x60

IPOPT_EOL		= 0		#end of option list
IPOPT_END		= IPOPT_EOL
IPOPT_NOP		= 1
IPOPT_NOOP		= IPOPT_NOP

IPOPT_RR		= 7 		#record packet route
IPOPT_TS		= 68		#timestamp
IPOPT_TIMESTAMP		= IPOPT_TS
IPOPT_SECURITY		= 130		#provide s, c, h, tcc
IPOPT_SEC		= IPOPT_SECURITY
IPOPT_LSRR		= 131		#loose source route
IPOPT_SATID		= 136		#satnet id
IPOPT_SID		= IPOPT_SATID
IPOPT_SSRR		= 137		#strict source route
IPOPT_RA		= 148		#router alert

#
#Offsets to fields in options other than EOL and NOP
#
IPOPT_OPTVAL		= 0		#option ID
IPOPT_OLEN		= 1		#option length
IPOPT_OFFSET		= 2		#offset within option
IPOPT_MINOFF		= 4		#min value of above

MAX_IPOPTLEN		= 40

#
#flag bits for ip options
#
IPOPT_TS_TSONLY		= 0		#timestamps only
IPOPT_TS_TSANDADDR	= 1		#timestamps and address
IPOPT_TS_PRESPEC	= 3		#specified modules only

#
#bits for security (not byte swapped)
#
IPOPT_SECUR_UNCLASS	= 0x0000
IPOPT_SECUR_CONFID	= 0xf135
IPOPT_SECUR_EFTO	= 0x789a
IPOPT_SECUR_MMMM	= 0xbc4d
IPOPT_SECUR_RESTR	= 0xaf13
IPOPT_SECUR_SECRET	= 0xd788
IPOPT_SECUR_TOPSECRET	= 0x6bc5

#
#Internet implementation parameters
#
MAXTTL			= 255		#maximum time to live
IPDEFTTL		= 64		#default ttl
IPFRAGTTL		= 60		#ttl for frags, slowhz
IPTTLDEC		= 1		#subtracted when forwarding

IP_MSS			= 576		#default maximum segment size

end
