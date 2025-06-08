import threading
import socket
import scapy.all as scapy
from collections import defaultdict
import datetime
import random
import subprocess
import requests
import time
import csv
import requests
import os
import socket
import netifaces
import scapy.all as scapy
import ipaddress
import networkx as nx
from ReportGenerator import Report_Generator

AnalyzerLogo = """


\033[35m
 /$$   /$$             /$$                                       /$$            
| $$$ | $$            | $$                                      | $$            
| $$$$| $$  /$$$$$$  /$$$$$$   /$$  /$$  /$$  /$$$$$$   /$$$$$$ | $$   /$$      
| $$ $$ $$ /$$__  $$|_  $$_/  | $$ | $$ | $$ /$$__  $$ /$$__  $$| $$  /$$/      
| $$  $$$$| $$$$$$$$  | $$    | $$ | $$ | $$| $$  \ $$| $$  \__/| $$$$$$/       
| $$\  $$$| $$_____/  | $$ /$$| $$ | $$ | $$| $$  | $$| $$      | $$_  $$       
| $$ \  $$|  $$$$$$$  |  $$$$/|  $$$$$/$$$$/|  $$$$$$/| $$      | $$ \  $$      
|__/  \__/ \_______/   \___/   \_____/\___/  \______/ |__/      |__/  \__/      
                                                                                
                                                                                
                                                                                
  /$$$$$$                      /$$                                              
 /$$__  $$                    | $$                                              
| $$  \ $$ /$$$$$$$   /$$$$$$ | $$ /$$   /$$ /$$$$$$$$  /$$$$$$   /$$$$$$       
| $$$$$$$$| $$__  $$ |____  $$| $$| $$  | $$|____ /$$/ /$$__  $$ /$$__  $$      
| $$__  $$| $$  \ $$  /$$$$$$$| $$| $$  | $$   /$$$$/ | $$$$$$$$| $$  \__/      
| $$  | $$| $$  | $$ /$$__  $$| $$| $$  | $$  /$$__/  | $$_____/| $$            
| $$  | $$| $$  | $$|  $$$$$$$| $$|  $$$$$$$ /$$$$$$$$|  $$$$$$$| $$            
|__/  |__/|__/  |__/ \_______/|__/ \____  $$|________/ \_______/|__/            
                                   /$$  | $$                                    
                                  |  $$$$$$/                                    
                                   \______/                                     
                                   
                                                                                                                                                 
\033[0m                                                                        

Author: Kassam Dakhlalah               
Github: kassam-99                      
Version: 1.0, 28 May 2024               
This project is open source
For any information on editing         
the project, please refer to Analyzer.txt                                   
                                                                          

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
            print(f"[!] Error reading MAC vendor CSV file: {e}")
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
                    "MAC_Address": mac_address
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
                mac_address
            )

        except Exception as e:
            print(f"[!] An error occurred: {e}")
            return None, None, None, None, None, None, None, None, None, None


    def ARP_DiscoverHosts(self, maxHostgroup=5, verbose=False, mapping=False, save_to_file=False):
        try:
            network_data = self.GetNetworkData(PrintDetails=verbose)
            if network_data is None:
                print("[!] Failed to get network data.")
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
            print(f"[!] Error during ARP host discovery: {e}")
            
            
            
            

class Analyzer:
    def __init__(self):
        self.PrivateScanner = Discover()
        

    def identify_devices_by_traffic(self, duration=60, verbose=False):
        """
        Identifies devices on the network by analyzing their traffic patterns.
        """
        try:
            traffic_patterns = defaultdict(set)
            device_profiles = {}
            def packet_callback(packet):
                if packet.haslayer(scapy.IP):
                    src_ip = packet[scapy.IP].src
                    dst_ip = packet[scapy.IP].dst
                    traffic_patterns[src_ip].add(dst_ip)                    
                    # Check if the device's traffic profile has changed
                    prev_profile = device_profiles.get(src_ip)
                    new_profile = f"Communicates with {len(traffic_patterns[src_ip])} unique destinations"
                    if prev_profile != new_profile:
                        device_profiles[src_ip] = new_profile
                        
                        # Print the updated profile
                        if verbose:
                            print(f"[+] Device {src_ip}: {new_profile}")

            print(f"[*] Starting to sniff network traffic for {duration} seconds...")
            scapy.sniff(timeout=duration, prn=packet_callback, store=0)

            print("[$] Done! Device identification by traffic patterns complete.")
            return device_profiles
        except Exception as e:
            print(f"[!] Error during device identification by traffic: {e}")
            return {}
    
    
    def monitor_network_traffic(self, interface=None, duration=60, verbose=False, save_to_file=False, file_path='captured_packets.pcap', protocol_filter=None):
        """
        Monitors network traffic on a specified interface for a given duration.
        """
        try:
            if interface is None:
                self.PrivateScanner.GetNetworkData(PrintDetails=verbose)
                interface = self.PrivateScanner.NetworkInterface
                if interface is None or not interface:
                    raise ValueError("Network interface could not be determined. Please specify an interface.")

            def protocol_filter_function(packet):
                if protocol_filter is None:
                    return True
                if 'TCP' in protocol_filter and packet.haslayer(scapy.TCP):
                    return True
                if 'UDP' in protocol_filter and packet.haslayer(scapy.UDP):
                    return True
                return False

            packets = scapy.sniff(iface=interface, timeout=duration, lfilter=protocol_filter_function)

            print(f"[$] Total packets captured: {len(packets)}")

            if verbose:
                for packet in packets:
                    if packet.haslayer(scapy.Ether):
                        print(f"Source: {packet[scapy.Ether].src}, Destination: {packet[scapy.Ether].dst}")
                    if packet.haslayer(scapy.IP):
                        print(f"IP Src: {packet[scapy.IP].src}, IP Dst: {packet[scapy.IP].dst}")

            print(f"[$] Packet summary:")
            packets.summary()

            if save_to_file:
                if not file_path.endswith('.pcap'):
                    file_path += '.pcap'
                scapy.wrpcap(file_path, packets)
                print(f"[$] Packets saved to {file_path}")

            protocol_count = {'TCP': 0, 'UDP': 0, 'Other': 0}
            for packet in packets:
                if packet.haslayer(scapy.TCP):
                    protocol_count['TCP'] += 1
                elif packet.haslayer(scapy.UDP):
                    protocol_count['UDP'] += 1
                else:
                    protocol_count['Other'] += 1
            print(f"[$] Traffic statistics: {protocol_count}")

            return packets
        except Exception as e:
            print(f"[!] Error during network traffic monitoring: {e}")
            return []


    def detect_rogue_access_points(self, known_ap_list, verbose=False):
        """
        Detects rogue access points by comparing discovered APs against a list of known APs.
        """
        try:
            def packet_callback(packet):
                if packet.haslayer(scapy.Dot11):
                    ssid = packet[scapy.Dot11].info.decode()
                    bssid = packet[scapy.Dot11].addr2
                    if bssid and (ssid, bssid) not in known_ap_list:
                        print(f"[!] Rogue AP detected: SSID={ssid}, BSSID={bssid}")
                        if verbose:
                            print(packet.summary())
    
            scapy.sniff(prn=packet_callback, store=0, timeout=60)
            print(f"[$] Done! Rogue access point detection complete.")
            
        except Exception as e:
            print(f"[!] Error during rogue access point detection: {e}")
    

    def detect_rogue_devices(self, known_devices, verbose=False):
        """
        Detects rogue devices by comparing discovered devices with a list of known devices.
        """
        try:
            rogue_devices = []
            self.PrivateScanner.ARP_DiscoverHosts(verbose=False, mapping=False, save_to_file=False)
            for host in self.PrivateScanner.DiscoveredData:
                if host["MAC"] not in known_devices:
                    rogue_devices.append(host)
                    if verbose:
                        print(f"Rogue device detected: {host['IP']} ({host['MAC']})")
            
            if verbose and not rogue_devices:
                print("[+] No rogue devices detected.")
            
            print(f"[$] Done! Rogue device detection completed.")
            return rogue_devices
        except Exception as e:
            print(f"[!] Error during rogue device detection: {e}")
            return []


    def query_dns(domain, dns_server, timeout=2):
        try:
            pkt = scapy.IP(dst=dns_server) / scapy.UDP(dport=53) / scapy.DNS(rd=1, qd=scapy.DNSQR(qname=domain))
            response = scapy.sr1(pkt, timeout=timeout, verbose=0)
            if response and response.haslayer(scapy.DNS):
                return response[scapy.DNS].an.rdata
        except Exception as e:
            return None
    
    
    def detect_dns_spoofing(self, target_domains, verbose=False):
        """
        Detects DNS spoofing by comparing DNS query results with known legitimate IP addresses.
        """
        try:
            spoofed_domains = []
            dns_servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]  # Google DNS, Cloudflare DNS, Quad9 DNS
            results_lock = threading.Lock()
    
            def check_domain(domain, legit_ips):
                nonlocal spoofed_domains
                resolved_ips = []
    
                threads = []
                for dns_server in dns_servers:
                    thread = threading.Thread(target=lambda: resolved_ips.append(self.query_dns(domain, dns_server)))
                    thread.start()
                    threads.append(thread)
    
                for thread in threads:
                    thread.join()
    
                unique_ips = set(resolved_ips) - {None}
                if not unique_ips.issubset(legit_ips):
                    with results_lock:
                        spoofed_domains.append((domain, list(unique_ips)))
                    if verbose:
                        for ip in unique_ips:
                            if ip not in legit_ips:
                                print(f"[!] DNS spoofing detected for {domain}: resolved IP {ip}")
    
            threads = []
            for domain, legit_ips in target_domains.items():
                thread = threading.Thread(target=check_domain, args=(domain, legit_ips))
                thread.start()
                threads.append(thread)
    
            for thread in threads:
                thread.join()
    
            print(f"[$] Done! DNS spoofing detection complete. Spoofed domains: {spoofed_domains}")
            return spoofed_domains
    
        except Exception as e:
            print(f"[!] Error during DNS spoofing detection: {e}")
            return []


    def check_dns_poisoning(self, domain, known_ip, verbose=False):
        """
        Checks for DNS poisoning by comparing the resolved IP address of a domain with a known IP address.
        """
        try:
            resolved_ip = socket.gethostbyname(domain)
            if resolved_ip != known_ip:
                print(f"[!] Potential DNS poisoning detected! {domain} resolved to {resolved_ip} instead of {known_ip}")
                if verbose:
                    print(f"[>] Expected IP: {known_ip}\n[>] Resolved IP: {resolved_ip}")
                return False
            else:
                print(f"[+] No DNS poisoning detected. {domain} resolved correctly to {known_ip}")
                return True
        except socket.error as e:
            print(f"[!] Error during DNS poisoning check: {e}")
            return False
    

    def detect_syn_flood(self, duration=60, threshold=1000, verbose=False):
        """
        Detects SYN flood attacks by monitoring the network for a specified duration and counting SYN packets.
        """
        
        try:
            syn_packets = []
    
            def packet_callback(packet):
                if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
                    syn_packets.append(packet)
    
            scapy.sniff(timeout=duration, prn=packet_callback, store=0)
    
            syn_count = len(syn_packets)
            if verbose:
                print(f"[+] SYN packets detected: {syn_count}")
    
            if syn_count > threshold:
                print(f"[!] Potential SYN flood attack detected! SYN packet count: {syn_count}")
            else:
                print(f"[+] No SYN flood attack detected. SYN packet count: {syn_count}")
        except Exception as e:
            print(f"[!] Error during SYN flood detection: {e}")
    
    
    def monitor_network_for_suspicious_activity(self, duration=60, verbose=False):
        """
        Monitors the network for suspicious activity by analyzing packet patterns.
        """
        try:
            self.PrivateScanner.GetNetworkData(PrintDetails=verbose)
            suspicious_sources = defaultdict(int)
    
            def packet_callback(packet):
                if packet.haslayer(scapy.IP) and packet[scapy.IP].dst == self.PrivateScanner.private_IPv4 and packet[scapy.IP].flags == "DF":
                    suspicious_sources[packet[scapy.IP].src] += 1
                    if verbose:
                        print(f"[!] Suspicious activity detected from {packet[scapy.IP].src}")
                        print(packet.summary())
    
            scapy.sniff(prn=packet_callback, store=0, timeout=duration, filter=f"dst {self.PrivateScanner.private_IPv4}")
            
            threshold = 5
            suspicious_sources = {source: count for source, count in suspicious_sources.items() if count >= threshold}
            
            print(f"[$] Done! Network monitoring for suspicious activity complete.")
            print(f"[-] Detected suspicious sources with {threshold} or more occurrences: {suspicious_sources}")
            
            return suspicious_sources
        except Exception as e:
            print(f"[!] Error during network monitoring for suspicious activity: {e}")
            return {}
    
    
    
    
    








class EngineAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()
        
        self.MainMenu = {
            "Analyzer" : lambda: self.AnalyzerOptions(FunctionKey="menu"),
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

    
    def AnalyzerOptions(self, FunctionKey='menu', **kwargs):

        if FunctionKey is None:
            FunctionKey = input("Enter Analyzer option: ")
        
        self.AnalyzerDic = {
            "Identifies devices on the network by analyzing their traffic patterns": lambda: self.identify_devices_by_traffic(
                duration=kwargs.get("duration", self.get_user_input("duration", 60)),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False))),
            "Monitors network traffic on a specified interface for a given duration": lambda: self.monitor_network_traffic(
                interface=kwargs.get("network interface", self.get_user_input("network interface")),
                duration=kwargs.get("duration", self.get_user_input("duration", 60)),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False)),
                save_to_file=kwargs.get("save_to_file", self.get_user_input("save_to_file", False)),
                file_path=kwargs.get("file path", self.get_user_input("file path", 'captured_packets.pcap')),
                protocol_filter=kwargs.get("protocol filter", self.get_user_input("protocol filter"))),
            "Detects rogue access points by comparing discovered APs against a list of known APs": lambda: self.detect_rogue_access_points(
                known_ap_list=kwargs.get("target", self.get_user_input("target")),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False))),
            "Detects rogue devices by comparing discovered devices with a list of known devices": lambda: self.detect_rogue_devices(
                known_devices=kwargs.get("target", self.get_user_input("target")),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False))),
            "Detects DNS spoofing by comparing DNS query results with known legitimate IP addresses": lambda: self.detect_dns_spoofing(
                target_domains=kwargs.get("target", self.get_user_input("target")),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False))),
            "Checks for DNS poisoning by comparing the resolved IP address of a domain with a known IP address": lambda: self.check_dns_poisoning(
                domain=kwargs.get("domain_name", self.get_user_input("domain_name")),
                known_ip=kwargs.get("destination", self.get_user_input("destination")),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False))),
            "Detects SYN flood attacks by monitoring the network for a specified duration and counting SYN packets": lambda: self.detect_syn_flood(
                duration=kwargs.get("duration", self.get_user_input("duration", 60)),
                threshold=kwargs.get("timeout", self.get_user_input("timeout", 2)),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False))),
            "Monitors the network for suspicious activity by analyzing packet patterns": lambda: self.monitor_network_for_suspicious_activity(
                duration=kwargs.get("duration", self.get_user_input("duration", 60)),
                verbose=kwargs.get("verbose", self.get_user_input("verbose", False)))
        }

        
        if FunctionKey in self.AnalyzerDic:
            self.AnalyzerDic[FunctionKey]()
        
        elif FunctionKey == "menu":
            return self.AnalyzerDic
            
        else:
            print(f"[\033[31m!\u001b[0m] Invalid FunctionKey: {FunctionKey}")


    def HelpOptions(self):
        with open("Analyzer.txt", "r") as HelpRead:
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











def main():
    engine = EngineAnalyzer()
    print(AnalyzerLogo)
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