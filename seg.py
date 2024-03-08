import os
import sys

filename = sys.argv[1]

if not os.path.exists('enum'):
    os.makedirs('enum')

with open(filename, 'r') as file:
    lines = file.readlines()

subdomains = [line.strip() for line in lines if 'subdomain' in line]
ips = [line.strip() for line in lines if 'subdomain_ip' in line]
ns_records = [line.strip() for line in lines if 'ns' in line]

with open('enum/subdomains.txt', 'w') as file:
    for subdomain in subdomains:
        file.write(subdomain + '\n')

with open('enum/ips.txt', 'w') as file:
    for ip in ips:
        file.write(ip + '\n')

with open('enum/ns_records.txt', 'w') as file:
    for ns in ns_records:
        file.write(ns + '\n')

with open('enum/description.txt', 'w') as file:
    file.write("Host: This is the main domain that was scanned, in this case, nmap.org.\n")
    file.write("MX: This field would contain a list of Mail Exchange (MX) records associated with the domain. In this case, it’s empty, indicating that no MX records were found.\n")
    file.write("NS: This is a list of Name Server (NS) records associated with the domain. Each record includes the IP address of the name server and the name of the name server itself. For example, ns2.linode.com. with IP 162.159.24.39.\n")
    file.write("Server: This is the type of web server software running on the main domain. In this case, it’s Apache/2.4.6 (CentOS).\n")
    file.write("Subdomains: This is a list of subdomains associated with the main domain. Each subdomain includes:\n")
    file.write("ASN: Autonomous System Number (ASN) details for the IP address of the subdomain. This includes the ASN itself, the CIDR block, the country code, the date the ASN was assigned, a description of the ASN, and the registry that assigned the ASN.\n")
    file.write("Server: The type of web server software running on the subdomain.\n")
    file.write("Subdomain: The name of the subdomain itself.\n")
    file.write("Subdomain IP: The IP address associated with the subdomain.\n")
    file.write("The error messages at the beginning indicate that there was an issue retrieving data from VirusTotal, likely due to access restrictions (status code 403 indicates forbidden access).\n")
