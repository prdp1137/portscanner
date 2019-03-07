import argparse
from socket import *
# Usage : python PortScanner.py -a 192.168.43.2 -p 21,80

def printBanner(socketConnection,targetPort):
	try:
		if (targetPort == 80):
			socketConnection.send("GET / HTTP/1.1\r\n\r\n")
		elif (targetPort == 443):
			socketConnection.send("GET / HTTPS/1.1\r\n\r\n")
		else:
			socketConnection.send("\r\n")
		results = socketConnection.recv(4096)

		print '[+] Banner : ' + str(results)
	except:
		print '[-] Banner not available\n'

def connScan(targetHost,targetPort):
	try:
		socketConnection=socket(AF_INET,SOCK_STREAM)
		# try to connect with the target
		socketConnection.connect((targetHost,targetPort))
		print'[+] %d tcp open'% targetPort
		printBanner(socketConnection,targetPort)
	except:
		# Print the failure results
		print '[-] %d tcp closed '% targetPort
	finally:
		# Close the socket object
		socketConnection.close()

def portScan(targetHost,targetPorts):
	try:
		# if -a was not an IP address this will resolve it to an IP
		targetIP = gethostbyname(targetHost)
	except :
		print "[-] Error : Unknown Host"
		exit(0)

	try:
		#if the domain can be resolved that's good, the results will be something like:
		tgtName = gethostbyaddr(targetIP)
		print "[+] Simple Port Scanner by 0xyg3n."
		print "[+] --- Scan result for : " + tgtName[0] + " --- "

	except:
		print "[+] Simple Port Scanner by 0xyg3n."
		print "[+] --- Scan result for : " + targetIP + " --- "

	setdefaulttimeout(10)

	# For each port number call the connScan function
	for targetPort in targetPorts:
		connScan(targetHost , int(targetPort))

def main():
	# Parse the command line arguments
	parser = argparse.ArgumentParser('Simple Port Scanner by 0xyg3n.')
	parser.add_argument("-a","--address",type=str, help="The target IP Address",default="127.0.0.1")
	parser.add_argument("-p","--port",type=str,help="The port number to connect with",default="4444")
	args = parser.parse_args()

	# Store the argument values
	ipAddress = args.address
	portNumbers = args.port.split(',')

	portScan(ipAddress,portNumbers)
if __name__ == "__main__":
	main()
