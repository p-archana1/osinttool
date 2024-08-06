import socket
import nmap

def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"IP address of {domain} is {ip_address}")
        return ip_address
    except socket.gaierror as e:
        print(f"Error retrieving IP address: {e}")
        return None

def scan_ports(ip_address):
    nm = nmap.PortScanner()
    nm.scan(ip_address, '1-1024')
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            lport = nm[host][proto].keys()
            for port in lport:
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}")

if __name__ == "__main__":
    domain = input("Enter the domain name: ")
    ip_address = get_ip_address(domain)
    if ip_address:
        scan_ports(ip_address)