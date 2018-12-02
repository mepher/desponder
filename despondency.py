import impacket,random,argparse,time,sys,os
from termcolor import colored
from impacket import smbconnection
from sys import stdin
from scapy.all import *
#feed the phish? inveigh the inveigh...
import urllib2, base64

def log( s , color=None):
	print colored('%s::  %s' % (time.ctime(),s),color)
	sys.stdout.flush()

def noise_login(target):
	log('sending noise to %s: ' % target ,'blue')
	wn=impacket.smbconnection.SMBConnection(target,target).login(RandString(size=random.randint(9,13)),RandString(size=random.randint(9,13)),RandString(size=random.randint(9,13)))

def basic_noise(target):
	request = urllib2.Request("http://"+str(target))
	base64string = base64.encodestring('%s:%s' % (RandString(size=random.randint(9,13)), RandString(size=random.randint(9,13)))).replace('\n', '')
	request.add_header("Authorization", "Basic %s" % base64string)   
	log('sending basic to %s: ' % target ,'green')
	urllib2.urlopen(request)
	
if __name__=='__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-t','--target', required=True)
	parser.add_argument('-c','--count', help="number of times to spam the target", required=False, default=1)
	#parser.add_argument('-d','--domain', required=False)
	
	args = parser.parse_args()
	
	for i in range(int(args.count)):
		noise_login(args.target)
		basic_noise(args.target)
#
