#!/usr/bin/python2.7
#import warnings
# works on kali, sept 17... :|
#warnings.filterwarnings("ignore")
from scapy.all import *
#print "import warnings are off. (blame scapy)"
'''
blah - dependencies
pip install mdns - NOPE
pip install scapy
pip install impacket
pip install netifaces
pip install pysmb
'''
import socket,os,time,random,argparse,fcntl,re 
import netifaces
from threading import Thread
import threading
import sys
from sys import stdin
from impacket import nmb
from termcolor import colored
import impacket
from impacket import smbconnection

def log( s , color=None):
	print colored('%s::  %s' % (time.ctime(),s),color)
	sys.stdout.flush()

def get_ip_address(ifname):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(s.fileno(),	0x8915, struct.pack('256s', ifname[:15]))[20:24])
	
def get_broadcast_address(ifname):
	return re.findall( r'[0-9]+(?:\.[0-9]+){3}', (re.search('broadcast(.+?)255',(str(netifaces.ifaddresses(ifname)))).group()))[0]

def noise_login(target):
	log('cowabunga >>> %s: ' % target ,'blue')
	wn=impacket.smbconnection.SMBConnection(target,target).login(RandString(size=random.randint(9,13)),RandString(size=random.randint(9,13)),RandString(size=random.randint(9,13)))

def noise_login_evil(target):
	log('cowabunga >>> %s: ' % target ,'blue')
	wn=impacket.smbconnection.SMBConnection(target,target).login(RandString(size=random.randint(9,13)),str(fuzz(Raw())),RandString(size=random.randint(9,13)))
	
	
class controller(Thread):
	
	def __init__(self):
		'''
		console / controller / global variable store thread.
		remember to use atomics.
		'''

		Thread.__init__(self)
		self.aparamter='hello globals!'
		
	def run(self):
		'''
		type in the console to send in commands.
		power debugging to be added later.
		'''
		log('Controller thread started. Enter help for help...')
		while True:
			line_in = stdin.readline()
			line_in_array = re.split(" ",line_in)
				
			if line_in == "quit\n":#or "q\n":
				'''
				quits.
				'''	
				#sys.exit(0)
				thispid = os.getpid()
				os.kill(thispid,9)
				
			if line_in == "help\n":
				log('quit to quit.')
				log('llmnr, nbtns to do another scan')
				
			if line_in == "llmnr\n":
				#log('jolly good luck ')
				data, addr1 = LLMNR.FindResponder()
				log((addr1[0],addr1[1], data[13:20]))
			
			if line_in == "nbtns\n":
				NBPositiveNameQueryResponse1 = NBTNS.FindResponder()
				log((NBPositiveNameQueryResponse1.addr_entries[0],NBPositiveNameQueryResponse1.get_netbios_name()))
			
			if line_in == "spam\n":
				for i in range(100):
					data, addr1 = LLMNR.FindResponder()
					log((addr1[0],addr1[1], data[13:20]))
					NBPositiveNameQueryResponse1 = NBTNS.FindResponder()
					log((NBPositiveNameQueryResponse1.addr_entries[0],NBPositiveNameQueryResponse1.get_netbios_name()))
			
			if line_in == "firell\n":
				noise_login(LLMNR.target)
			
			if line_in == "fireevil\n":
				noise_login_evil(LLMNR.target)
			
			
			# if line_in == "message\n":
				# line_in = None
				# log('enter message (max 15 chars), will be sent over NBTNS','blue')
				# message = str(input(':'))
				# NBMEssageResponse = NBTNS.NBTNSMessageResponder(message)
				# log((NBMEssageResponse.addr_entries[0],NBMEssageResponse.get_netbios_name()))

				
class LLMNRListener(Thread):
	
	def __init__(self):
		'''
		some clever nicked from the internet to get this to work.
		please note - seems a little more selective about detecting 
		packets than wireshark. ie you might see some in WS
		but this will ignore them
		No idea. TTL? src / dst ip / mac?
		'''
		Thread.__init__(self)
		self.running = True
		self.target=None
		'''
		set up the UDP socket.
		some serious socket fu going on here.
		'''
		self.MCAST_GRP 	= '224.0.0.252'
		self.MCAST_PORT	= 5355
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		#self.socket.setdefaulttimeout(3600) # 1 hour
		#self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
		self.sock.bind((callbackip, self.MCAST_PORT))
		# sufficently advanced technology is indistinguishable from magic.
		mreq = struct.pack('4sl', socket.inet_aton(self.MCAST_GRP ), socket.INADDR_ANY)
		self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)	
	
	def run(self):
		log('LLMNR listener started on UDP 5355')
		log('Send 3 random LLMNR queries. Responses Below')
		#LOOK AT THIS! scapy down a (multicast UDP) socket. WIN.
		#self.sock.sendto(str(LLMNRQuery(id=RandShort(), qd=DNSQR(qname=RandString(size=random.randint(9,13))))),('224.0.0.252',5355))
		try:
			data, addr1 = self.FindResponder()
			log((addr1[0],addr1[1], data[13:20]))
			data, addr2 = self.FindResponder()
			log((addr2[0],addr2[1], data[13:20]))
			data, addr3 = self.FindResponder()
			log((addr3[0],addr3[1], data[13:20]))
			if ((addr1[0] == addr2[0]) and (addr1[0] == addr3[0])):
				log('Looks like %s is a LLMNR responder!' % addr1[0],'green')
				#log('LLMNR.target set')
				self.target=addr1[0]
		except:
			log('LLMNR exception, nothing found')
		else:
			log('LLMNR nothing found')
		
	def FindResponder(self):
		#put the logging in the function, rather than repeat it everywhere....
		#log('sending LLMNR query','yellow')
		self.sock.settimeout(0.2)
		try:
			self.sock.sendto(str(LLMNRQuery(id=RandShort(), qd=DNSQR(qname=RandString(size=random.randint(9,13))))),('224.0.0.252',5355))
			#log('socket about to wait for response','yellow')
			data, addr = self.sock.recvfrom(1024)
			#log('socket has revieved response, now returning to calling function','yellow')
		except:
			log('LLMNR socket timed out.','yellow')
		return (data, addr)

		
class NBTNSListener(Thread):
	'''
	from impacket import nmb
	NBT = nmb.NetBIOS()
	NBT.setbroadcast('192.168.1.255')
	ans=NBT.gethostbyname(Randomstring)
	'''
	def __init__(self):

		Thread.__init__(self)
		self.running = True
		self.target=None
		self.NBT = nmb.NetBIOS()
		#log('#### Setting NBT  broadcast address. hardcoded slackness. FIX ####','red')
		self.NBT.set_broadcastaddr(broadcastip)
		
	def run(self):
		log('NBTNS started on UDP 137')
		log('Send 3 random NBTNS queries. Responses Below')
		try:
			NBPositiveNameQueryResponse1 = self.FindResponder()
			log((NBPositiveNameQueryResponse1.addr_entries[0],NBPositiveNameQueryResponse1.get_netbios_name()))
			NBPositiveNameQueryResponse2 = self.FindResponder()
			log((NBPositiveNameQueryResponse2.addr_entries[0],NBPositiveNameQueryResponse2.get_netbios_name()))
			NBPositiveNameQueryResponse3 = self.FindResponder()
			log((NBPositiveNameQueryResponse3.addr_entries[0],NBPositiveNameQueryResponse3.get_netbios_name()))
			if ((NBPositiveNameQueryResponse1.addr_entries[0] == NBPositiveNameQueryResponse2.addr_entries[0]) and (NBPositiveNameQueryResponse3.addr_entries[0] == NBPositiveNameQueryResponse1.addr_entries[0])):
				log('Looks like %s is a NBTNS responder!' % NBPositiveNameQueryResponse3.addr_entries[0],'green')
				#log('NBTNS.target set')
				self.target = NBPositiveNameQueryResponse3.addr_entries[0]
		except:
			log('NBTNS recieved nothing')
			
				
	def FindResponder(self):
		return self.NBT.gethostbyname(RandString(size=random.randint(9,13)))
		#put the logging in the function, rather than repeat it everywhere....
		#self.sock.sendto(str(LLMNRQuery(id=RandShort(), qd=DNSQR(qname=RandString(size=random.randint(9,13))))),('224.0.0.252',5355))
		#data, addr = self.sock.recvfrom(1024)
		#return (data, addr)		
		
	def NBTNSMessageResponder(self,message):
		log('Sending message (max 15 chars) over NBTNS : %s' % message,'blue')
		return self.NBT.gethostbyname(message[0:15])
		
class mDNSListener(Thread)	:
	# This one is the problem child. perhaps not included.
	def __init__(self):

		Thread.__init__(self)
		self.running = True
		'''
		set up the UDP socket.
		some serious socket fu going on here.
		'''
		self.MCAST_GRP 	= '224.0.0.251'
		self.MCAST_PORT	= 5353
		self.UDP_IP = '0.0.0.0'
		#self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
		#self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
		#self.sock.bind((callbackip, self.MCAST_PORT))
		# sufficently advanced technology is indistinguishable from magic.
		self.sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
		#log('mDNS listener binding to :%s' % self.UDP_IP,'red')
		self.sock.bind((self.UDP_IP, self.MCAST_PORT))
		mreq = struct.pack('4sl', socket.inet_aton(self.MCAST_GRP ), socket.INADDR_ANY)
		self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)	
	
	def run(self):
		log('mDNS listener started on UDP 5353')
		log('send 3 random mDNS queries')
		data, addr1 = self.FindResponder()
		log((addr1[0],addr1[1], data[13:20]))
		data, addr2 = self.FindResponder()
		log((addr2[0],addr2[1], data[13:20]))
		data, addr3 = self.FindResponder()
		log((addr3[0],addr3[1], data[13:20]))
		if ((addr1[0] == addr2[0]) and (addr1[0] == addr3[0])):
			log('looks like %s is a mDNS responder!' % addr1[0],'green')
		
	def FindResponder(self):
		#put the logging in the function, rather than repeat it everywhere....
		#the horror...
		self.heskey=True
		self.heskeycount=0
		#due to poor coding, this is somehow necessary to avoid mDNS LANSpamming....
		self.sanity=True
		self.sanitycount=0
		while ((self.heskey == True)):
			self.sock.sendto((str(DNS(qd=DNSQR(qname=RandString(size=random.randint(9,13)))))),(self.MCAST_GRP,self.MCAST_PORT))
			data, addr = self.sock.recvfrom(1024)
			self.sanitycount+=1
			if ((addr[0] != callbackip) or (self.sanitycount > 10)):
				self.heskey = False
			else:
				self.heskeycount+=1
		log('heskeys:%s' % self.heskeycount , 'red')
		return (data, addr)
		
if __name__=='__main__':
	#while True:
	parser = argparse.ArgumentParser()
	parser.add_argument('-I','--interface', help='The interface to launch everything on', required=False, default='eth0')
	#parser.add_argument('-h','--help', help='Help goes here.') # broken..
	args = parser.parse_args()
	log('Local IP on: ' + args.interface +' '+ get_ip_address(args.interface))
	log('Local Broadcast address on: ' + args.interface +' '+ get_broadcast_address(args.interface))
	
	#console		= controller()
	#console.start()
	
	callbackip	= get_ip_address(args.interface)
	broadcastip = get_broadcast_address(args.interface)
	
	LLMNR 		= LLMNRListener()
	LLMNR.start()	
	
	time.sleep(0.1)
	
	NBTNS		= NBTNSListener()
	NBTNS.start()
	
	time.sleep(0.1)
	
	if ((LLMNR.target==None)and(NBTNS.target==None)):
		log('No Responder\'s identified. exit','green')

	#mDNSx		= mDNSListener()	
	#mDNSx.start()
    #mDNS no worky
