import socket 
import subprocess 
import sys
from datetime import datetime

# Clear the screen 
subprocess.call('clear', shell=True)

# Ask for input 
remoteServer = input("Enter a remote host to scan: ")
remoteServerIP = socket.gethostbyname(remoteServer)

# Print a banner with information on which host we are about to scan 
print("-" * 60)
print("Please wait, scanning remote host", remoteServerIP)
print("-" * 60)

# Check what time the scan started 
t1 = datetime.now()

# Using the range function to specify ports (here it will scans all ports between 1 and 1024)

# We also put in some error handling for catching errors 
try:
    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            print("Port {}: Open".format(port))
        sock.close()

except KeyboardInterrupt:
    print("You pressed Ctrl+C")
    sys.exit()

except socket.gaierror:
    print('Hostname could not be resolved. Exiting')

# Scan services running on each port
def scan_services(remoteServerIP, port):
    try:
        service = socket.getservbyport(port)
    except:
        service = "Unknown"

    print("Service running on port {}: {}".format(port, service))

# Identify potential security risks associated with each service 
def scan_vulnerabilities(remoteServerIP, port, service):
    if service == "http":
        print("Potential security risk: HTTP service detected on port {}".format(port))
    elif service == "telnet":
        print("Potential security risk: Telnet service detected on port {}".format(port))
    elif service == "ftp":
        print("Potential security risk: FTP service detected on port {}".format(port))

# Generate reports based on the results of the scan 
def generate_report(remoteServerIP, open_ports):
    print("-" * 60)
    print("Scan Report: {}".format(remoteServerIP))
    print("-" * 60)
    if len(open_ports) > 0:
        print("Open Ports: ")
        for port in open_ports:
            print("\t{}".format(port))
    else:
        print("No open ports found.")

# Main function 
def main():
    open_ports = []
    try:
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP, port))
            if result == 0:
                open_ports.append(port)
                print("Port {}: Open".format(port))
                scan_services(remoteServerIP, port)
                service = socket.getservbyport(port)
                scan_vulnerabilities(remoteServerIP, port, service)
            sock.close()
        generate_report(remoteServerIP, open_ports)
    except KeyboardInterrupt:
        print("You pressed Ctrl+C")
        sys.exit()

    except socket.gaierror:
        print("Hostname could not be resolved. Exiting")
        sys.exit()

    except socket.error:
        print("Could not connect to server")
        sys.exit()

if __name__ == "__main__":
    main()
