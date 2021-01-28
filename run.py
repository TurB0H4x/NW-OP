from scapy.all import *
import socket
import SocketServer
import SimpleHTTPServer
import urllib
import sys
import pyfiglet

#Make sniffer

def snif():
   pkt = sniff(iface="eth0", count=65000, filter= "tcp", prn=lambda x: x.show())

#Make arp Scanner

def scanArp():
	for i in range(1,50):
		ip = "192.168.1." + str(i)
		arpRequest = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
		arpResponse = srp1(arpRequest, timeout=1, verbose=0)
		if arpResponse:
			print "\t[*] IP: " + arpResponse.psrc + ", MAC :" + arpResponse.hwsrc

#Web Server

class HTTPHand(SimpleHTTPServer.SimpleHTTPRequestHandler):
	def do_GET(self):
		SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

#Directory BruteForce

def dirForce():
	url_target = raw_input("Entre URL of Target : ")
	wordlist = raw_input("Entre wordlist name : ")
	words = open(str(wordlist), 'r')
	try:
		for line in words:
			ww = line.strip()
			req = urllib.urlopen(url_target + "/" + ww)
			code = req.code
			if code == 200:
				print "[*] Directory Found %s/%s" %(url_target, ww)
	except:
		print "[*] Somethings Wrong ."
		sys.exit()
	except KeyboardInterrupt:
		print "\nPrograme exiting ..."
		sys.exit()


banner = pyfiglet.figlet_format("NW-OP")
print banner + "\tTwitter : @TurB0H4x\n"
print "[1] Packets Sniffer \n[2] ARP scanner \n[3] Start WebServer \n[4] BruteForce Directory \n[5] Ports Scanner"
op = str(input("Please chose one for Run it : "))

if op == "1":
	print "Sniffing...\n"
	snif()
if op == "2":
	print "\nStart Scaning..."
	scanArp()
if op == "3":
	local_ip = raw_input("Entre your local ip :")
	http = SocketServer.TCPServer((local_ip, 8080), HTTPHand)
	print "Web Server Started on %s:8080 \n" % local_ip
	http.serve_forever()

if op == "4":
	dirForce()

if op == "5":
	ports = [25, 80, 443, 20, 21, 23, 143, 3389, 22, 53, 67, 68, 110, 88, 139, 445]
	host = raw_input("Entre Target host or IP : ")
	print "Start Scannig  Ports ..."
	try:
		for port in ports:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			socket.setdefaulttimeout(1)
			conn = s.connect_ex((host,port))
			if conn == 0:
				print "[*] Port %s Is Open | Service : %s" %(port, socket.getservbyport(port))
			s.close()
	except socket.error:
		print "\n Problem in Server "
		sys.exit()
	except KeyboardInterrupt:
		print "\nPrograme exiting ..."
		sys.exit()

else:
    pass
