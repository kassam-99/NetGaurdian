import threading
import socket
import scapy.all as scapy
from collections import defaultdict
from Discover import Discover




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
    
    
    
    
    







if __name__ == "__main__":

    
    # Example Usage:

    #Analyzer().identify_devices_by_traffic(duration=60, verbose=True)
    
    Analyzer().monitor_network_traffic(duration=60, verbose=True, save_to_file=True, file_path='captured_packets.pcap', protocol_filter=['TCP'])

    known_aps = [("HomeNetwork", "00:11:22:33:44:55"), ("OfficeNetwork", "66:77:88:99:AA:BB")]
    #Analyzer().detect_rogue_access_points(known_ap_list=known_aps, verbose=True)

    target_domains = {
        "example.com": ["93.184.216.34"],
        "another-example.com": ["192.0.2.1"]
    }
    
    #Analyzer().detect_dns_spoofing(target_domains, verbose=True)
    
    #Analyzer().detect_syn_flood(duration=60, threshold=500, verbose=True)
    
    #Analyzer().monitor_network_for_suspicious_activity(duration=120, verbose=True)
    