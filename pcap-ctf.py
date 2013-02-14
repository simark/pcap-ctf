import sys
import pcapy
import os
import struct

class PacketProcessor(object):
	def __init__(self, outfile):
		self.out = open(outfile, "wb")
		self.i = 0
		
	def process_packet(self, pkthdr, data):
		# Compute timestamp
		sec, microsec = pkthdr.getts()
		ts = sec * 1000000000 + microsec * 1000
		
		# Write timestamp
		self.out.write(struct.pack("Q", ts))
		
		# Write arbitrary argument
		self.out.write(struct.pack("Q", self.i))
		self.i = self.i + 1

def print_metadata(metadata_path):
	f = open(metadata_path, "w")
	f.write("/* CTF 1.8 */\n")
	f.write("typealias integer { size = 64; align = 64; signed = false; } := uint64_t;\n")
	f.write("trace {\n")
	f.write("\tmajor = 1;\n")
	f.write("\tminor = 8;\n")
	f.write("\tbyte_order = le;\n")
	f.write("};\n\n")
	
	f.write("struct event_header {\n")
	f.write("\tuint64_t timestamp;\n")
	f.write("};\n\n")
	
	f.write("stream {\n")
	f.write("\tevent.header := struct event_header;\n")
	f.write("};\n\n")
	
	f.write("event {\n")
	f.write("\tname = network_packet;\n")
	f.write("\tfields := struct { uint64_t arg; };\n")
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
