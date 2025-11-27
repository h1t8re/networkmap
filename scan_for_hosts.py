import sys
import os
import subprocess
import threading
import shutil

def check_for_root():
	print('\nVerification of admin rights...',end="")
	if not os.geteuid() == 0:
		sys.exit('\nPlease run this script as rootd.')

def install_binary(b=""):
	check_for_root()
	if not os.system('apt install '+b)==0:
		sys.exit('\n\nInstallation error..')

try: 
    from scapy.all import *
except ImportError:
    install_binary("python3-scapy")
    from scapy.all import *

if not shutil.which("arp"):
    install_binary("net-tools")

class Iface:
	number = 0
	name = ""
	mac = ""
	ips = []	
	default_ip = ""

	def __init__(self, number=0, name="", mac=""):
		self.name = name
		self.number = number
		self.mac = mac

	def get_number(self):
		return self.number

	def get_name(self):
		return self.name
	
	def get_mac(self):
		return self.mac
	
	def get_ip_list(self):
		return self.ips
	
	def get_default_ip(self):
		if len(self.default_ip) >= 8:
			return self.default_ip
		else: 
			return None

	def set_default_ip(self, ip):
		if ip in self.ips:
			self.default_ip = ip

	def add_ip(self, ip):
		self.ips.append(ip)
	
	def print_iface(self):
		print(str(self.number)+": ", end="")
		print(self.name+": ", end="")
		print(self.mac, end="\n")
		for ip in self.ips:
			print(ip, end="\n")
		print("\n")	

def runcommand(command=[], input_data=b'', timeout="5"):
    try:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        std_out, std_err = proc.communicate(input=b''+input_data)
        std_out = std_out.strip()
    except FileNotFoundError:
        print("Error running command")
        exit()
    proc.kill()
    return std_out, std_err

def scan_for_hosts(iface=None):
    default_ip = iface.get_default_ip()
    reply = None
    if not default_ip:
        return 0	
    l = default_ip.split(".")[:-1]
    network = l[0] + '.' + l[1] + '.' + l[2] + '.'
    for i in range(1, 255):
        ip = network + str(i)
        print("Scanning "+ip+" ... ", end="")
        std_out, std_err = runcommand(["ping", "-c", "1", "-w", "4", ip])
        if b'1 received' in std_out:
            print("up", end=" ")
            if ip == default_ip:
                print("\n")
                continue
            stdout, stderr = runcommand(["arp", "-n", "-D", ip])
            stdout = stdout.decode('utf-8')
            lines = stdout.split("\n")
            hwaddr = lines[1].split(" ")
            hwaddr = [x for x in hwaddr if x != '']
            print("with hwaddr ", end="")
            print(hwaddr[2], end="\n")
        else:
            print("down", end="\n")	

def main():
	interface_number = 1
	choosed_interface_number = " "
	ifaces = scapy.interfaces.get_if_list()
	for iface in ifaces:
		print(str(interface_number)+": "+iface, end="\n") 
		interface_number = interface_number +1
	print("\n\n")
	print("Select the number of interface to use: ", end="\n")
	iface_number = input()
	iface_number = iface_number.strip('\n')
	try:
		interface_num = int(iface_number)
	except ValueError:
		sys.exit("Please select a valid number\n")
	print("Getting interface configuration ...", end="")
	interface_config = scapy.interfaces.resolve_iface(ifaces[interface_num-1])
	iface = Iface(interface_num, ifaces[interface_num-1], interface_config.mac)
	print(" done", end="\n")
	print("Storing interface configuration ...", end="")
	iface.add_ip(interface_config.ip)
	iface.set_default_ip(interface_config.ip)
	print(" done", end="\n")
	iface.print_iface()
	up_ips = scan_for_hosts(iface)
	
	return 0

if __name__ == "__main__":
	main()
