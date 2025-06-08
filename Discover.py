import datetime
import random
import re
import subprocess
import uuid
from matplotlib import pyplot as plt
import requests
import time
import csv
import requests
import os
import socket
import struct
import netifaces
import scapy.all as scapy
import ipaddress
import networkx as nx
import matplotlib.pyplot as plt
from ReportGenerator import Report_Generator

DiscoverLogo = """

\033[35m

 /$$$$$$$  /$$                                                            
| $$__  $$|__/                                                            
| $$  \ $$ /$$  /$$$$$$$  /$$$$$$$  /$$$$$$  /$$    /$$ /$$$$$$   /$$$$$$ 
| $$  | $$| $$ /$$_____/ /$$_____/ /$$__  $$|  $$  /$$//$$__  $$ /$$__  $$
| $$  | $$| $$|  $$$$$$ | $$      | $$  \ $$ \  $$/$$/| $$$$$$$$| $$  \__/
| $$  | $$| $$ \____  $$| $$      | $$  | $$  \  $$$/ | $$_____/| $$      
| $$$$$$$/| $$ /$$$$$$$/|  $$$$$$$|  $$$$$$/   \  $/  |  $$$$$$$| $$      
|_______/ |__/|_______/  \_______/ \______/     \_/    \_______/|__/      

\033[0m                                                                        

Author: Kassam Dakhlalah               
Github: kassam-99                      
Version: 1.0, 28 May 2024               
This project is open source
For any information on editing         
the project, please refer to Discover.txt                                   
                                                                          

"""






class Discover:
    def __init__(self, NetworkIP_CiderIPv4: str = None, NetworkIP: str = None, 
                SubnetCiderNotation: int = None, subnet_mask: str = None, 
                NetworkInterface: str = None, WaitingTimeDelay: int = 3,
                Orginal_MAC: str = None, MOCK_MAC: list = None,
                MACsite: str = None):
        
        self.Reporter = Report_Generator()
        self.NetworkIP_CiderIPv4 = NetworkIP_CiderIPv4
        self.NetworkIP = NetworkIP
        self.SubnetCiderNotation = SubnetCiderNotation
        self.subnet_mask = subnet_mask
        self.WaitingTime = WaitingTimeDelay
        self.Orginal_MAC = Orginal_MAC
        self.MOCK_MAC = MOCK_MAC
        self.NetworkInterface = NetworkInterface
        self.MACsite = MACsite or "https://macvendorlookup.com/api/v2/"
        self.private_IPv4 = None
        self.mac_vendor_data = self.read_mac_vendor_csv("MAC.CSV") # Specify path of MAC.CSV
        self.network_graph = nx.Graph()
             
        self.DiscoveredData = []
        self.HostData = {
            "No.": None,
            "IP": None,
            "MAC": None,
            "Vendor": None,
            "Network IP": None,
            "Network Subnet": None,
            "Protocol": None,
            "Time & Date" : None
        }
    
    
    def read_mac_vendor_csv(self, csv_file):
        """
        This function reads the MAC vendor data from a CSV file.
        You should provide the path of that file.
        The CSV file should have these columns -
        Registry, Assignment, Organization Name, Organization Address
        """
        try:
            mac_vendor_data = {}
            with open(csv_file, 'r') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    mac_prefix = row.get('Assignment')[:4].upper() 
                    vendor = row.get('Organization Name')
                    if mac_prefix and vendor:
                        mac_vendor_data[mac_prefix] = vendor
            return mac_vendor_data
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] Error reading MAC vendor CSV file: {e}")
            return {}


    def get_vendor_info(self, macaddress):
        """
        This function retrieves the vendor information for a given MAC address.
        """
        try:
            test = macaddress
            mac_prefix = test[:8].replace(':', '').upper()[:4]
            vendor = self.mac_vendor_data.get(mac_prefix)
            if vendor is not None:
                return vendor + " from MAC.csv"
            else:
                if self.MACsite != None:
                    macsend = self.MACsite + macaddress
                    response = requests.get(macsend, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        if data:
                            company_info = data[0]
                            company_name = company_info.get('company', 'Unknown')
                            return company_name + " from MacVendorLookup API"
                        elif response.status_code == 204:
                            return "No vendor information available - 204"
                        else:
                            return f"Error: {response.status_code}"
                    else:
                        return f"Error: {response.status_code}"
                else:
                    return "Unknown"
        except requests.exceptions.RequestException as e:
            return f"Error while getting vendor from URL"


    def change_mac(self, RandomMAC=False, NetworkInterface=None, MAC=None, Reverse_Mode=False):
        """
        This function changes the MAC address of the network interface.
        """
        
        try:
            if Reverse_Mode == False:
                if RandomMAC == True:
                    new_mac = ":".join(["{:02x}".format(random.randint(0, 255)) for _ in range(6)])
                else:
                    new_mac = MAC
                
                if not new_mac:
                    print("[\033[31m!\u001b[0m] No MAC address provided.")
                    return
                
                interface = self.NetworkInterface or NetworkInterface
                if not interface:
                    print("[\033[31m!\u001b[0m] No network interface provided.")
                    return
                
                self.MOCK_MAC = new_mac
                print(f"[>] Changing MAC address of {interface} to {new_mac}")
                subprocess.call(["sudo", "ifconfig", interface, "down"])
                subprocess.call(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
                subprocess.call(["sudo", "ifconfig", interface, "up"])
                
            else:
                interface = self.NetworkInterface or NetworkInterface
                if not interface:
                    print("[\033[31m!\u001b[0m] No network interface provided.")
                    return
                self.change_mac(RandomMAC=False, NetworkInterface=interface, MAC=self.Orginal_MAC, Reverse_Mode=False)
                
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] Error changing MAC address: {e}")


    def GetNetworkData(self, PrintDetails=False, save_to_file=False):
        """
        This function retrieves the network data, including the private IP address, 
        network interface, subnet mask, network address, and other details.
        """
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface == 'lo':
                    continue
                addresses = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addresses:
                    ipv4_info = addresses[netifaces.AF_INET][0]
                    ip_address = ipv4_info['addr']
                    if ipaddress.IPv4Address(ip_address).is_private:
                        private_IPv4 = ip_address
                        public_IPv4 = subprocess.run(['curl', 'ifconfig.me'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        network_interface = iface
                        subnet_mask_str = ipv4_info['netmask']
                        subnet_cidr = sum(bin(int(x)).count('1') for x in subnet_mask_str.split('.'))
                        subnet_mask = ipaddress.IPv4Address(subnet_mask_str)
                        Network_AddressCiderIPv4 = ipaddress.IPv4Network(ip_address + '/' + str(subnet_cidr), strict=False)
                        broadcast_address = Network_AddressCiderIPv4.broadcast_address
                        usable_hosts = list(Network_AddressCiderIPv4.hosts())
                        total_hosts = len(usable_hosts) + 2  # +1 for network address, +1 for broadcast address
                        usable_host_ip_range = f"{usable_hosts[0]} - {usable_hosts[-1]}"
                        network_IPv4 = Network_AddressCiderIPv4.network_address
                        mac_address = addresses[netifaces.AF_LINK][0]['addr']
                        gateways = netifaces.gateways()
                        default_gateway_ip = gateways['default'][netifaces.AF_INET][0]
                        arp_request = scapy.ARP(pdst=default_gateway_ip)
                        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
                        arp_request_broadcast = broadcast / arp_request
                        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
                        for sent, received in answered_list:
                            default_gateway_mac = received.hwsrc
                        
                        break
            if PrintDetails == True:
                print(f"[>] Current network data of {Network_AddressCiderIPv4}")
                print(f"[-] Network address: {network_IPv4}")
                print(f"[-] Subnet CIDR: {subnet_cidr}")
                print(f"[-] Current Subnet: {subnet_mask}")
                print(f"[-] Broadcast Address: {broadcast_address}")
                print(f"[-] Your private IPv4: {private_IPv4}")
                print(f"[-] Your public IPv4: {public_IPv4.stdout.strip()}")
                print(f"[-] Total Number of Hosts: {total_hosts}")
                print(f"[-] Number of Usable Hosts: {len(usable_hosts)}")
                print(f"[-] Usable Host IPv4 Range: {usable_host_ip_range}")
                print(f"[-] Network Interface: {network_interface}")
                print(f"[-] MAC Address: {mac_address}")
                print(f"[-] Default Gateway IP: {default_gateway_ip}")
                print(f"[-] Default Gateway MAC: {default_gateway_mac}")

                

            if save_to_file == True:
                NetworkData = {
                    "Network": str(Network_AddressCiderIPv4),
                    "Subnet": str(subnet_mask),
                    "Broadcast": str(broadcast_address),
                    "Private_IPv4": private_IPv4,
                    "Public_IPv4": public_IPv4.stdout.strip(),
                    "Total_Hosts": total_hosts,
                    "Usable_Hosts": len(usable_hosts),
                    "Usable_Hosts_Range": usable_host_ip_range,
                    "Network_Interface": network_interface,
                    "MAC_Address": mac_address,
                    "Default_Gateway_IP": default_gateway_ip,
                    "Default_Gateway_MAC": default_gateway_mac
                }
                NetworkList = [NetworkData]
            
                self.Reporter.CSV_GenerateReport(Data=NetworkList)
                self.Reporter.TXT_GenerateReport(Data=NetworkList)
            
            self.NetworkIP_CiderIPv4 = Network_AddressCiderIPv4 
            self.NetworkIP = network_IPv4 
            self.SubnetCiderNotation = subnet_cidr
            self.subnet_mask = subnet_mask
            self.private_IPv4 = private_IPv4
            self.NetworkInterface = network_interface
            if self.Orginal_MAC == None:
                self.Orginal_MAC = mac_address 
            
            return (
                Network_AddressCiderIPv4,
                network_IPv4,
                subnet_cidr,
                subnet_mask,
                broadcast_address,
                private_IPv4,
                public_IPv4.stdout.strip(),
                total_hosts,
                len(usable_hosts),
                usable_host_ip_range,
                network_interface,
                mac_address,
                default_gateway_ip,
                default_gateway_mac
            )
    
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] An error occurred: {e}")
            return None, None, None, None, None, None, None, None, None, None, None, None, None


    def ARP_DiscoverHosts(self, maxHostgroup=5, verbose=False, mapping=False, save_to_file=False):
        try:
            network_data = self.GetNetworkData(PrintDetails=verbose)
            if network_data is None:
                print("[\033[31m!\u001b[0m] Failed to get network data.")
                return
            print("[>] ARP - Scanning network for active hosts...\n")
            arp_request = scapy.ARP(pdst=f"{self.NetworkIP_CiderIPv4}")
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            IPorder = 1

            while IPorder <= maxHostgroup:
                request_broadcast = broadcast / arp_request
                answered_packets, _ = scapy.srp(request_broadcast, timeout=1, verbose=False)

                for sent_packet, received_packet in answered_packets:
                    if received_packet:
                        duplicate_found = False
                        for data in self.DiscoveredData:
                            if data.get("IP") == received_packet.psrc:
                                duplicate_found = True
                                break
                        if not duplicate_found:
                            vendor_info = self.get_vendor_info(received_packet.hwsrc)
                            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            self.HostData = {
                                "No.": IPorder,
                                "IP": received_packet.psrc,
                                "MAC": received_packet.hwsrc,
                                "Vendor": vendor_info,
                                "Network IP": self.NetworkIP,
                                "Network Subnet": self.SubnetCiderNotation,
                                "Protocol": "ARP",
                                "Time & Date": timestamp
                            }
                            self.DiscoveredData.append(self.HostData)
                            if verbose == True:
                                print(f"[{IPorder}] {timestamp}\n[-] {received_packet.psrc}\n[-] {received_packet.hwsrc}\n[-] {vendor_info}\n")
                            
                            IPorder += 1
                            if IPorder > maxHostgroup:
                                break
                            
                time.sleep(self.WaitingTime)
            
            print("[$] Done!, scanning using ARP method")
            
            if save_to_file == True:
                self.Reporter.CSV_GenerateReport(Data=self.DiscoveredData)
                self.Reporter.TXT_GenerateReport(Data=self.DiscoveredData)

            if mapping == True:
                self.NetworkMapper()
                              
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] Error during ARP host discovery: {e}")
            

    def ARP_DiscoverHost(self, HostIP, verbose=False, save_to_file=False):
        """
        This function is used to discover a single host using ARP method.
        """
        try:
            
            print(f"[*] Discovering {HostIP} using ARP method")
            network_data = self.GetNetworkData(PrintDetails=verbose)
            if network_data is None:
                print("[\033[31m!\u001b[0m] Failed to get network data.")
                return
            arp_request = scapy.ARP(pdst=HostIP)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            
            for sent, received in answered_list:
                vendor_info = self.get_vendor_info(received.hwsrc)
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.HostData = {
                    "No.": "Specific",
                    "IP": HostIP,
                    "MAC": received.hwsrc,
                    "Vendor": vendor_info,
                    "Network IP": self.NetworkIP,
                    "Network Subnet": self.SubnetCiderNotation,
                    "Protocol": "ARP",
                    "Time & Date": timestamp
                }
                if verbose == True:
                    print(f"[Specific] {timestamp}\n[-] {received.psrc}\n[-] {received.hwsrc}\n[-] {vendor_info}\n")
                    
            if save_to_file == True:
                self.Reporter.CSV_GenerateReport(Data=self.DiscoveredData)
                self.Reporter.TXT_GenerateReport(Data=self.DiscoveredData)
                              
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] Error during ARP host discovery: {e}")    
        
        
    def ICMP_DiscoverHosts(self, maxHostgroup=5, verbose=False, mapping=False, save_to_file=False):
        try:
            network_data = self.GetNetworkData(PrintDetails=verbose)
            if network_data is None:
                print("[\033[31m!\u001b[0m] Failed to get network data.")
                return
            
            print("[>] ICMP - Scanning network for active hosts...\n")
            
            ping = 'timeout 0.2 ping -c 1 '
            IPorder = 1
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            for decimal_ip in range(int(self.NetworkIP_CiderIPv4.network_address) + 1, int(self.NetworkIP_CiderIPv4.broadcast_address)):
                if decimal_ip == self.private_IPv4:
                    continue
                
                accion = ping + str(decimal_ip)
                output = os.popen(accion).read()
                
                if 'ttl=64' in output or 'ttl=128' in output:
                    dotted_ip = socket.inet_ntoa(struct.pack('!L', decimal_ip))
                    self.HostData = {
                        "No.": IPorder,
                        "IP": dotted_ip,
                        "MAC": None,
                        "Vendor": None,
                        "Network IP": self.NetworkIP,
                        "Network Subnet": self.SubnetCiderNotation,
                        "Protocol": "ICMP",
                        "Time & Date": timestamp
                    }
                    self.DiscoveredData.append(self.HostData)
                    if verbose == True:
                        print(f"[{IPorder}] {timestamp}\n[-] IP: {dotted_ip}\n")
                    IPorder += 1
                    if IPorder > maxHostgroup:
                        break
                    time.sleep(self.WaitingTime)

            print("[$] Done!, scanning using ICMP method")
            
            if save_to_file == True:
                self.Reporter.CSV_GenerateReport(Data=self.DiscoveredData)
                self.Reporter.TXT_GenerateReport(Data=self.DiscoveredData)

            if mapping == True:
                self.NetworkMapper()
                     
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] Error during ICMP host discovery: {e}")
    
    
    def ICMP_DiscoverHost(self, target, ping_count=4, verbose=False, mapping=False, save_to_file=False):
        try:
            network_data = self.GetNetworkData(PrintDetails=verbose)
            if network_data is None:
                print("[\033[31m!\u001b[0m] Failed to get network data.")
                return
            
            if verbose==True:
                print("[>] ICMP - Scanning network for active host...\n")
            ping_command = f'timeout 0.2 ping -c 1 {target}'
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            for i in range(ping_count):
                output = os.popen(ping_command).read()
                if verbose==True:
                    print(output)
                if "1 received" in output or "1 packets received" in output:
                    status = "Host is active"
                else:
                    status = "Host is inactive or unreachable"
                if verbose==True:
                    print(f"Ping attempt {i + 1}/{ping_count}: {status}")
            
            self.HostData = {
                "No.": str(uuid.uuid4()),
                "IP": target,
                "MAC": None,
                "Vendor": None,
                "Network IP": self.NetworkIP,
                "Network Subnet": self.SubnetCiderNotation,
                "Protocol": "ICMP",
                "Time & Date": timestamp,
                "Status": status
            }
            self.DiscoveredData.append(self.HostData)

            print(f"[$] Done!, scanning using ICMP method {target}")

            if save_to_file == True:
                self.Reporter.CSV_GenerateReport(Data=self.DiscoveredData)
                self.Reporter.TXT_GenerateReport(Data=self.DiscoveredData)
            
            if mapping == True:
                self.NetworkMapper()
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] Error during ICMP host discovery: {e}")
                    

    def NetworkMapper(self):
        try:
            self.network_graph.clear()
            for host in self.DiscoveredData:
                self.network_graph.add_node(host['IP'], label=f"\n\n{host['No.']}\n\n{host['MAC']}\n{host['Time & Date']}\n{host['Vendor']}")
                self.network_graph.add_edge(self.NetworkIP, host['IP'])

            plt.figure(figsize=(10, 8))
            pos = nx.spring_layout(self.network_graph)
            labels = nx.get_node_attributes(self.network_graph, 'label')
            nx.draw(self.network_graph, pos, with_labels=True, node_size=700, node_color='skyblue')
            nx.draw_networkx_labels(self.network_graph, pos, labels, font_size=10)
            plt.title('Network Map')
            plt.show()

        except Exception as e:
            print(f"[\033[31m!\u001b[0m] Error updating network graph: {e}")
            

    def traceroute(self, destination=None, max_hops=30, timeout=2, verbose=False):
        """
        Traces the route to a destination IP address.
        """
        if destination is None:
            print("[\033[31m!\u001b[0m] Failed to trace .")
            return
    
        try:
            port = 33434
            ttl = 1
            if verbose==True:
                print("Traceroute to", destination, "(", socket.gethostbyname(destination), "),", max_hops, "hops max")
            hop_ips = []  # List to store hop IP addresses
            while True:
                ip_packet = scapy.IP(dst=destination, ttl=ttl)
                udp_packet = scapy.UDP(dport=port)
                packet = ip_packet / udp_packet
                reply = scapy.sr1(packet, timeout=timeout, verbose=0)
                if reply is None:
                    if verbose==True:
                        print(f"{ttl}\t*")
                        
                elif reply.type == 3:
                    hop_ip = reply.src
                    hop_ips.append(hop_ip)
                    if verbose==True:
                        print(f"{ttl}\t{hop_ip}")
                    break
                else:
                    hop_ip = reply.src
                    hop_ips.append(hop_ip)
                    if verbose==True:
                        print(f"{ttl}\t{hop_ip}")
                ttl += 1
                if ttl > max_hops:
                    if verbose==True:
                        print("Max hops exceeded.")
                    break

            if verbose==True:
                print("Hop IP addresses:")
            for i, hop_ip in enumerate(hop_ips, start=1):
                if verbose==True:
                    print(f"{i}. {hop_ip}")
                    
            print(f"[$] Done!, tracing route, {destination}")
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] Error during traceroute: {e}")


    def dns_lookup(self, domain_name=None, verbose=False):
        """
        Performs a DNS lookup for a given domain name.
        """
        try:
            if domain_name is None:
                print("[\033[31m!\u001b[0m] Failed to lookup .")
                return
            result = socket.gethostbyname(domain_name)
            if verbose:
                print(f"DNS lookup for {domain_name}: {result}")
            print(f"[$] Done! DNS lookup for {domain_name}")
            return result
        except socket.error as e:
            print(f"[\033[31m!\u001b[0m] Error during DNS lookup: {e}")
            return None


    def os_fingerprinting(self, target_ip=None, verbose=False):
        """
        Performs OS fingerprinting on a target IP address to identify the operating system.
        """
        try:
            if target_ip is None:
                print("[\033[31m!\u001b[0m] Failed to check fingerprint .")
                return
            os_signatures = {
                "Linux": {"ttl": 64, "window": 5840},
                "Windows": {"ttl": 128, "window": 8192},
                "FreeBSD": {"ttl": 64, "window": 65535},
                "MacOS": {"ttl": 64, "window": 65535},
            }
            
            pkt = scapy.IP(dst=target_ip) / scapy.TCP(dport=80, flags="S")
            response = scapy.sr1(pkt, timeout=1, verbose=0)
            
            if response:
                ttl = response[scapy.IP].ttl
                window = response[scapy.TCP].window
                for os, signature in os_signatures.items():
                    if ttl == signature["ttl"] and window == signature["window"]:
                        if verbose:
                            print(f"[+] OS detected: {os}")
                        return os
                if verbose:
                    print("[+] OS not recognized from the signature database.")
            else:
                if verbose:
                    print("[\033[31m!\u001b[0m] No response received from the target.")
            return None
        
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] Error during OS fingerprinting: {e}")
            return None
        

    def IP_forwarding(self, status=False):
    
        try:
            # True: Enable,  False: Disable
            # Set IP forwarding
            ip_forward_value = "1" if status else "0"
            subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={ip_forward_value}"], check=True)
            
            # Update sysctl.conf
            sysctl_conf_path = "/etc/sysctl.conf"
            ip_forward_line = f"net.ipv4.ip_forward={ip_forward_value}\n"
            
            # Read current sysctl.conf content
            with open(sysctl_conf_path, "r") as sysctl_conf:
                lines = sysctl_conf.readlines()
            
            # Update or add the ip_forward_line
            with open(sysctl_conf_path, "w") as sysctl_conf:
                found = False
                for line in lines:
                    if re.match(r"net\.ipv4\.ip_forward\s*=\s*\d", line):
                        if not found:
                            sysctl_conf.write(ip_forward_line)
                            found = True
                    else:
                        sysctl_conf.write(line)
                if not found:
                    sysctl_conf.write(ip_forward_line)

            subprocess.run(["sysctl", "-p", sysctl_conf_path], check=True)
            
            if status:
                print("[+] IP forwarding has been enabled.")
            else:
                print("[-] IP forwarding has been disabled.")
        except subprocess.CalledProcessError as e:
            print(f"[\033[31m!\u001b[0m] A subprocess error occurred: {e}")
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] An error occurred: {e}")














class EngineDisover(Discover):
    def __init__(self):
        super().__init__()
        
        self.MainMenu = {
            "Discover" : lambda: self.DiscoverOptions(FunctionKey="menu"),
            "Help" : self.HelpOptions,
            "Exit" : lambda: os.abort()
        }
        

    def get_user_input(self, param_name, default_value=None):
        while True:
            try:
                user_input = input(f"[\033[36m>\u001b[0m] Enter value for {param_name} (default: {default_value}): ").strip()
                if not user_input:
                    return default_value
                elif isinstance(default_value, bool):
                    return user_input.lower() in ['true', 'yes', '1']
                elif isinstance(default_value, int):
                    return int(user_input)
                elif isinstance(default_value, float):
                    return float(user_input)
                else:
                    return user_input
            except ValueError:
                print("[\033[31m!\u001b[0m] Invalid input. Please enter a valid value.")

    
    def DiscoverOptions(self, FunctionKey=None, **kwargs):
        if FunctionKey is None:
            FunctionKey = input("[\033[36m>\u001b[0m] Enter Discover option: ")
        
        self.DiscoverDic = {
            "Get Network Data": lambda:self.GetNetworkData(
                PrintDetails=kwargs.get("print Details", self.get_user_input("print Details", True)),
                save_to_file=kwargs.get("save to file", self.get_user_input("save to file", False))),
            "Change MAC address": lambda:self.change_mac(
                RandomMAC=kwargs.get("random MAC", self.get_user_input("random MAC", False)),
                NetworkInterface=kwargs.get("network interface", self.get_user_input("network interface")),
                MAC=kwargs.get("MAC", self.get_user_input("MAC")),
                Reverse_Mode=kwargs.get("reverse Mode", self.get_user_input("reverse Mode", False))),
            "Discover hosts using ARP": lambda:self.ARP_DiscoverHosts(
                maxHostgroup=kwargs.get("Maximum host group", self.get_user_input("Maximum host group", 5)),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False)),
                mapping=kwargs.get("mapping", self.get_user_input("mapping", False)),
                save_to_file=kwargs.get("save to file", self.get_user_input("save to file", False))),
            "Discover host using ARP": lambda:self.ARP_DiscoverHost(
                HostIP=kwargs.get("IP", self.get_user_input("IP")),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False)),
                save_to_file=kwargs.get("save to file", self.get_user_input("save to file", False))),
            "Discover hosts using ICMP": lambda:self.ICMP_DiscoverHosts(
                maxHostgroup=kwargs.get("Maximum host group", self.get_user_input("Maximum host group", 5)),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False)),
                mapping=kwargs.get("mapping", self.get_user_input("mapping", False)),
                save_to_file=kwargs.get("save to file", self.get_user_input("save to file", False))),
            "ICMP Discover Host": lambda:self.ICMP_DiscoverHost(
                target=kwargs.get("target", self.get_user_input("target")),
                ping_count=kwargs.get("ping count", self.get_user_input("ping count", 4)),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False)),
                mapping=kwargs.get("mapping", self.get_user_input("mapping", False)),
                save_to_file=kwargs.get("save to file", self.get_user_input("save to file", False))),
            "Traceroute": lambda:self.traceroute(
                destination=kwargs.get("destination", self.get_user_input("destination")),
                max_hops=kwargs.get("max hops", self.get_user_input("max hops", 30)),
                timeout=kwargs.get("timeout", self.get_user_input("timeout", 2)),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False))),
            "DNS Lookup": lambda:self.dns_lookup(
                domain_name=kwargs.get("domain name", self.get_user_input("domain name")),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False))),
            "OS Fingerprinting": lambda:self.os_fingerprinting(
                target_ip=kwargs.get("target", self.get_user_input("target")),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False))),
            "IP forwarding": lambda: self.IP_forwarding(
                status=kwargs.get("status", self.get_user_input("status", False))),
            
        }
        
        if FunctionKey in self.DiscoverDic:
            self.DiscoverDic[FunctionKey]()

        elif FunctionKey == "menu":
            return self.DiscoverDic

        else:
            print(f"Invalid FunctionKey: {FunctionKey}")


    def HelpOptions(self):
        with open("Discover.txt", "r") as HelpRead:
            print(HelpRead.read())
            

    def ViewFunc(self, option):
        if isinstance(option, str) and option.lower() == "all":
            print("==============================")
            for index, view in enumerate(self.MainMenu):
                print(f"\033[34m{index+1}\u001b[0m) {view}")
            print("==============================")
        
        elif isinstance(option, int):
            if 1 <= option <= len(self.MainMenu):
                key = list(self.MainMenu.keys())[option - 1]
                submenu = self.MainMenu[key]()
                if submenu:
                    self.print_submenu(submenu)
                    sub_option = input("[\033[36m>\u001b[0m] Select to run: ")
                    self.handle_submenu(submenu, sub_option)
                else:
                    print(f"{option}. {key}")
            else:
                print(f"[\033[31m!\u001b[0m] Please choose an option within the range 1 - {len(self.MainMenu)}")

        elif isinstance(option, str):
            option = option.capitalize()
            if option in self.MainMenu:
                submenu = self.MainMenu[option]()
                if submenu:
                    self.print_submenu(submenu)
                    sub_option = input("[\033[36m>\u001b[0m] Select to run: ")
                    self.handle_submenu(submenu, sub_option)
                else:
                    print(f"{option}. {submenu}")
            else:
                print(f"[\033[31m!\u001b[0m] Invalid option: {option}")
                

    def print_submenu(self, submenu):
        print("==============================")
        for idx, sub_key in enumerate(submenu):
            print(f"\033[34m{idx+1}\u001b[0m) {sub_key}")
        print("==============================")


    def handle_submenu(self, submenu, sub_option):
        if sub_option.isdigit():
            sub_option = int(sub_option)
            if 1 <= sub_option <= len(submenu):
                sub_key = list(submenu.keys())[sub_option - 1]
                submenu[sub_key]()
            else:
                print(f"[\033[31m!\u001b[0m] Please choose an option within the range 1 - {len(submenu)}")

        else:
            print(f"[\033[31m!\u001b[0m] Invalid option: {sub_option}")

    def Sudo_Mode(self):
        if not 'SUDO_UID' in os.environ.keys():
            print("[\033[31m!\u001b[0m] Try running this program with sudo.")
            exit()




def main():
    engine = EngineDisover()
    engine.Sudo_Mode()
    print(DiscoverLogo)
    while True:
        engine.ViewFunc("all")
        try:
            option = input("\n[\033[36m>\u001b[0m] Enter your choice (or '\033[31mexit\u001b[0m' to quit): ").strip().lower()
            if option == 'exit':
                engine.MainMenu["Exit"]()
                break
            elif option.isdigit():
                engine.ViewFunc(int(option))
            else:
                engine.ViewFunc(option.capitalize())

        except ValueError:
            print("[\033[31m!\u001b[0m] Invalid input. Please enter a number or '\033[31mexit\u001b[0m' to quit.")
        except KeyError:
            print("[\033[31m!\u001b[0m] Invalid option. Please choose a valid option number or name.")
        except Exception as e:
            print(f"[\033[31m!\u001b[0m] An unexpected error occurred: {e}")

            

if __name__ == "__main__":
    main()
    
    