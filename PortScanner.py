import argparse
from socket import *
# Usage : python PortScanner.py -a 192.168.43.2 -p 21,80

def printBanner(connSock,tgtPort):
	try:
		if (tgtPort == 80):
			connSock.send("GET / HTTP/1.1 \r\n")
		else:
			connSock.send("\r\n")
		results = connSock.recv(4096)

		print '[+] Banner : ' + str(results)
	except:
		print '[-] Banner not available\n'

def connScan(tgtHost,tgtPort):
	try:
		connSock=socket(AF_INET,SOCK_STREAM)
		# try to connect with the target
		connSock.connect((tgtHost,tgtPort))
		print'[+] %d tcp open'% tgtPort
		printBanner(connSock,tgtPort)
	except:
		# Print the failure results
		print '[-] %d tcp closed '% tgtPort
	finally:
		# Close the socket object
		connSock.close()

def portScan(tgtHost,tgtPorts):
	try:
		# if -a was not an IP address this will resolve it to an IP
		tgtIP = gethostbyname(tgtHost)
	except :
		print "[-] Error : Unknown Host"
		exit(0)

	try:
		#if the domain can be resolved that's good, the results will be something like:
		tgtName = gethostbyaddr(tgtIP)
		print "[+] --- Scan result for : " + tgtName[0] + " --- "

	except:
		print "[+] --- Scan result for : " + tgtIP + " --- "

	setdefaulttimeout(10)

	# For each port number call the connScan function
	for tgtPort in tgtPorts:
		connScan(tgtHost , int(tgtPort))

def main():
	# Parse the command line arguments
	parser = argparse.ArgumentParser('Simple Port Scanner by Pr0d33p.')
	parser.add_argument("-a","--address",type=str, help="The target IP Address",default="127.0.0.1")
	parser.add_argument("-p","--port",type=str,help="The port number to connect with",default="4444")
	args = parser.parse_args()

	# Store the argument values
	ipaddress = args.address
	portNumbers = args.port.split(',')

	portScan(ipaddress,portNumbers)
if __name__ == "__main__":
	main()
