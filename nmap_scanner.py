import nmap
import argparse
import sys


def nmap_scan(target_host, target_port):

	scanner = nmap.PortScanner()
	scanner.scan(target_host, target_port)
	host_state = scanner[target_host].state()
	port_state = scanner[target_host]['tcp'][int(target_port)]['state']

	if host_state == "up":
		print("[+] {} tcp/{} {}".format(target_host, target_port, port_state))


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-H", dest="hostname", help="Specify the hostname or IP address of your target.")
	parser.add_argument("-p", dest="ports", help="Specify the port(s) seperated by a comma (,) to scan on your target.")


	if len(sys.argv) != 5:
		parser.print_help(sys.stderr)
		sys.exit(1)

	args = parser.parse_args()

	hostname = args.hostname
	ports = args.ports.split(",")

	for port in ports:
		nmap_scan(hostname, port)



if __name__ == "__main__":
	main()