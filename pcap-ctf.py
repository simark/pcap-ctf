import sys
import pcapy
import os
import struct
from impacket import ImpactDecoder
from impacket.ImpactPacket import IP, TCP, UDP, ICMP

class PacketProcessor(object):
	def __init__(self, outfile):
		self.out = open(outfile, "wb")
		self.decoder = ImpactDecoder.EthDecoder()

	def process_packet(self, pkthdr, data):
		# Compute timestamp
		sec, microsec = pkthdr.getts()
		ts = sec * 1000000000 + microsec * 1000

		# Write timestamp
		self.out.write(struct.pack("Q", ts))

		# Le paquet decode avec impacket... on peut s'amuser avec ca
		# Voir http://code.google.com/p/impacket/source/browse/trunk/impacket/ImpactPacket.py#495
		decoded = self.decoder.decode(data)

		# Write event id
		if isinstance(decoded.child(), IP):
			if isinstance(decoded.child().child(), TCP):
				# TCP
				self.out.write(struct.pack("B", 3))
				self.write_eth_fields(decoded)
				self.write_ip_fields(decoded.child())
				self.write_tcp_fields(decoded.child().child())
			else:
				# IP
				self.out.write(struct.pack("B", 2))
				self.write_eth_fields(decoded)
				self.write_ip_fields(decoded.child())
		else:
			# Eth
			self.out.write(struct.pack("B", 1))
			self.write_eth_fields(decoded)

	def write_eth_fields(self, decoded):
		dst = decoded.get_ether_dhost()
		src = decoded.get_ether_shost()
		eth_type = decoded.get_ether_type()

		self.out.write(struct.pack("%sB" % len(dst), *dst))
		self.out.write(struct.pack("%sB" % len(src), *src))
		self.out.write(struct.pack("H", eth_type))

	def write_ip_fields(self, decoded):
		dst = decoded.get_ip_dst()
		src = decoded.get_ip_src()

		self.out.write(dst + "\0")
		self.out.write(src + "\0")

	def write_tcp_fields(self, decoded):
		dst_port = decoded.get_th_dport()
		src_port = decoded.get_th_sport()

		self.out.write(struct.pack("H", dst_port))
		self.out.write(struct.pack("H", src_port))

def print_metadata(metadata_path):
	f = open(metadata_path, "w")
	f.write("/* CTF 1.8 */\n")
	f.write("typealias integer { size = 64; align = 8; signed = false; } := uint64_t;\n")
	f.write("typealias integer { size = 32; align = 8; signed = false; base = 16;} := uint32_t;\n")
	f.write("typealias integer { size = 16; align = 8; signed = false; base = 16;} := uint16_t;\n")
	f.write("typealias integer { size = 8; align = 8; signed = false; base = 16;} := uint8_t;\n")

	f.write("trace {\n")
	f.write("\tmajor = 1;\n")
	f.write("\tminor = 8;\n")
	f.write("\tbyte_order = le;\n")
	f.write("};\n\n")

	f.write("struct event_header {\n")
	f.write("\tuint64_t timestamp;\n")
	f.write("\tuint8_t id;\n")
	f.write("};\n\n")

	f.write("struct eth_fields {\n")
	f.write("\tuint8_t dst[6];\n")
	f.write("\tuint8_t src[6];\n")
	f.write("\tuint16_t eth_type;\n")
	f.write("};\n\n")

	f.write("struct ip_fields {\n")
	f.write("\tstruct eth_fields eth;\n")
	f.write("\tstring dst;\n")
	f.write("\tstring src;\n")
	f.write("};\n\n")

	f.write("struct tcp_fields {\n")
	f.write("\tstruct ip_fields eth;\n")
	f.write("\tuint16_t dst;\n")
	f.write("\tuint16_t src;\n")
	f.write("};\n\n")

	f.write("stream {\n")
	f.write("\tevent.header := struct event_header;\n")
	f.write("};\n\n")

	f.write("event {\n")
	f.write("\tid = 0;\n")
	f.write("\tname = unknown_packet;\n")
	f.write("\tfields := struct { uint8_t dummy; };\n")
	f.write("};\n\n")

	f.write("event {\n")
	f.write("\tid = 1;\n")
	f.write("\tname = ethernet_packet;\n")
	f.write("\tfields := struct eth_fields;\n")
	f.write("};\n\n")

	f.write("event {\n")
	f.write("\tid = 2;\n")
	f.write("\tname = ip_packet;\n")
	f.write("\tfields := struct ip_fields;\n")
	f.write("};\n\n")

	f.write("event {\n")
	f.write("\tid = 3;\n")
	f.write("\tname = tcp_packet;\n")
	f.write("\tfields := struct tcp_fields;\n")
	f.write("};\n\n")


def main(argv):
	if len(argv) != 3:
		print("Usage: " + argv[0] + " [pcap file] [ctf folder]")
		sys.exit(1)

	pcap_filename = argv[1]
	ctf_path = argv[2]

	if not os.path.exists(pcap_filename):
		print("Source file does not exist.")
		sys.exit(1)

	if os.path.exists(ctf_path):
		print("Output folder exists, aborting.");
		sys.exit(1)

	# open source
	reader = pcapy.open_offline(pcap_filename)

	# create trace folder
	os.mkdir(ctf_path)

	# print metadata
	print_metadata(ctf_path + "/metadata")

	# open stream file
	pp = PacketProcessor(ctf_path + "/stream")

	# process packets
	reader.loop(-1, pp.process_packet)

if __name__ == "__main__":
	main(sys.argv)
