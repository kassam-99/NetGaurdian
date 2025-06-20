import threading
import os
from Analyzer import Analyzer
from Discover import Discover
from PortScanner import PortScanner
from TaskAutomation import TaskAutomation







pink_color = '\033[95m'
yellow_color = '\033[33m'
reset_color = '\033[0m'

logo_NetGuardian = f"""
{yellow_color}
               ⢀⣀⣀⣴⣆⣠⣤⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀  ⠀⠀⠈⣻⣿⣯⣘ ⠹⣧⣤⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀   ⠀⠛⠿⢿⣿⣷⣾⣯⠉⠀ {pink_color}  
               ⠛⠿⢿⣿⣷⣾⣯⠉⠀⠀⠀⠀⠀⠀
                ⠀⣾⣿⠜⣿⡍⠀⠀⠀⠀⠀⠀⠀ 
              ⠀⠀⣸⣿⠁⠀⠘⣿⣆⠀⠀⠀⠀⠀⠀
              ⠀⢠⣿⡟⠃⡄⠀⠘⢿⣆⠀⠀⠀⠀⠀
            ⠀⠀⣾⣿⣁⣋⣈ ⣤⣮⣿⣧⡀⠀{reset_color}
   ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⣤⣤⣤⣶⣦⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀
   ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡿⠛⠉⠙⠛⠛⠛⠛⠻⢿⣿⣷⣤⡀⠀⠀⠀⠀⠀
   ⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⠋⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠈⢻⣿⣿⡄⠀⠀⠀⠀
   ⠀⠀⠀⠀⠀⠀⠀⣸⣿⡏⠀⠀⠀⣠⣶⣾⣿⣿⣿⠿⠿⠿⢿⣿⣿⣿⣄⠀⠀⠀
   ⠀⠀⠀⠀⠀⠀⠀⣿⣿⠁⠀⠀⢰⣿⣿⣯⠁⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣷⡄⠀
   ⠀⠀⣀⣤⣴⣶⣶⣿⡟⠀⠀⠀⢸⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣷⠀
   ⠀⢰⣿⡟⠋⠉⣹⣿⡇⠀⠀⠀⠘⣿⣿⣿⣿⣷⣦⣤⣤⣤⣶⣶⣶⣶⣿⣿⣿⠀
   ⠀⢸⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀
   ⠀⣸⣿⡇⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠉⠻⠿⣿⣿⣿⣿⡿⠿⠿⠛⢻⣿⡇⠀⠀
   ⠀⣿⣿⠁⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣧⠀⠀
   ⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀
   ⠀⣿⣿⠀⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠀⠀
   ⠀⢿⣿⡆⠀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀
   ⠀⠸⣿⣧⡀⠀⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠃⠀⠀
   ⠀⠀⠛⢿⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⣰⣿⣿⣷⣶⣶⣶⣶⠶⠀⢠⣿⣿⠀⠀⠀
   ⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡇⠀⣽⣿⡏⠁⠀⠀⢸⣿⡇⠀⠀⠀
   ⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀⠀⠀⠀⣿⣿⡇⠀⢹⣿⡆⠀⠀⠀⣸⣿⠇⠀⠀⠀
   ⠀⠀⠀⠀⠀⠀⠀⢿⣿⣦⣄⣀⣠⣴⣿⣿⠁⠀⠈⠻⣿⣿⣿⣿⡿⠏⠀⠀⠀⠀
   ⠀⠀⠀⠀⠀⠀⠀⠈⠛⠻⠿⠿⠿⠿⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
\n\u001b[34mI am not an \033[31mimposter\u001b[0m\u001b[34m, but I know who is.\u001b[0m\n

Welcome to \033[33mNetGuardian\u001b[0m, 
Comprehensive network security and automation tool designed to facilitate efficient network 
\033[36mdiscovery\u001b[0m, \033[36mscanning\u001b[0m, \033[36mmonitoring\u001b[0m, and \033[36mreporting\u001b[0m. 

The project integrates several key components to provide a holistic approach to network management and security analysis.
"""

print(logo_NetGuardian)


    











class Engine(Analyzer, Discover, PortScanner, TaskAutomation):
    
    def __init__(self):
        self.MainMenu = {
            "Discover" : lambda: self.DiscoverOptions(FunctionKey="menu"),
            "Scanner" : self.ScannerOptions,
            "Analyzer" : lambda: self.AnalyzerOptions(FunctionKey="menu"),
            "Automation" :  self.TaskAutomationOptions,
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


    
    
    
    
    



    def to_bool(self, value: str) -> bool:
        true_values = {"true", "t", "yes", "y", "1"}
        false_values = {"false", "f", "no", "n", "0"}
        value = value.strip().lower()
        if value in true_values:
            return True
        elif value in false_values:
            return False
        else:
            print(f"[\033[33m!\033[0m] Unrecognized input '{value}', defaulting to False.")
            return False







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
 

    







    def ScannerOptions(self, **kwargs) -> None:
        targets = kwargs.get("targets", self.get_user_input("Targets (IP, domain, or 'file:filename.txt')", "192.168.1.1"))
        
        if isinstance(targets, str) and targets.startswith("file:"):
            filepath = targets.split("file:")[-1]
            targets = self.read_targets_from_file(filepath)
            if not targets:
                print("\033[31m[!] No valid targets found in the file.\033[0m")
                return
    
        ports = kwargs.get("ports", self.get_user_input(
            "Ports (e.g., 80,443, 1-100 or all_tcp_only/all_udp_only/all_common_ports/full_range/well_known/registered/dynamic)", 
            "80,443"
        ))
    
        transport = kwargs.get("transport", self.get_user_input("Transport (tcp/udp/all)", "tcp"))
        scan_type = kwargs.get("scan_type", self.get_user_input("Scan type (connect/syn/ack/window/fin/xmas/null/all)", "syn"))
        timeout = float(kwargs.get("timeout", self.get_user_input("Timeout (seconds)", "2")))
        retries = int(kwargs.get("retries", self.get_user_input("Retries", "3")))
        timing = kwargs.get("timing", self.get_user_input("Timing (T0-T5)", "T3"))
        
        verbose_input = kwargs.get("verbose", self.get_user_input("Verbose (True/False)", "True"))
        save_input = kwargs.get("save_to_file", self.get_user_input("Save report to file (True/False)", "False"))
        
        verbose = self.to_bool(verbose_input)
        save_to_file = self.to_bool(save_input)
    
        scan_types = ["connect", "syn", "ack", "window", "fin", "xmas", "null"]
        transports = ["tcp", "udp"]
    
        selected_scan_types = scan_types if scan_type == "all" else [scan_type]
        selected_transports = transports if transport == "all" else [transport]
    
        for selected_transport in selected_transports:
            for selected_scan in selected_scan_types:
                print(f"\n\033[34m--- Scanning with transport: {selected_transport.upper()}, scan type: {selected_scan.upper()} ---\033[0m")
                self.scanner = PortScanner(
                                targets=targets,
                                transport_layer=selected_transport,  
                                ports=ports,
                                timeout=timeout,
                                retries=retries,
                                verbose=verbose,
                                timing_template=timing  
                            )
                self.scanner.scan(save_to_file=save_to_file, scan_type=selected_scan)
    
                if save_to_file:
                    print("\033[32m[✓] Reports saved as CSV, TXT, and JSON.\033[0m")
    
    
    
    






    def TaskAutomationOptions(self, TaskAutomationFunc=None, FunctionKey=None, **kwargs):
        TaskAutomationFunc = TaskAutomation()
        self.selected_mode = None
        FuncTasks = {}
        modes = {
            'sequential': TaskAutomationFunc._sequential_mode,
            'timed': lambda: TaskAutomationFunc._timed_mode(kwargs.get("interval", 0)),
            'safe': lambda: TaskAutomationFunc._safe_mode(kwargs.get("time_sleep", 3)),
            'hardcore': TaskAutomationFunc._hardcore_mode,
            'focus': TaskAutomationFunc._focus_mode,
            'live_monitor': TaskAutomationFunc._live_monitor_mode,
            'smart': lambda: TaskAutomationFunc._smart_mode(kwargs.get("delay", 5)),
        }
    
        if FunctionKey is None:
            print("[\033[36m>\u001b[0m] Select functions to automate:")
            print("\033[34m1\u001b[0m) Discover")
            print("\033[34m2\u001b[0m) Scanner")
            print("\033[34m3\u001b[0m) Analyzer")
            while True:
                selected_functions_input = input("[\033[36m>\u001b[0m] Enter the numbers of the functions to automate (comma-separated): ")
                selected_functions = [int(x.strip()) for x in selected_functions_input.replace(" ", "").split(",") if x.strip()]
                if all(fn in [1, 2, 3] for fn in selected_functions):
                    break
                else:
                    print("[\033[31m!\u001b[0m] Invalid function number. Please enter valid numbers (1, 2, 3).")
        else:
            selected_functions = [FunctionKey]
    
        if not selected_functions:
            print("[\033[31m!\u001b[0m] No functions selected.")
            return
    
        function_map = {
            1: "Discover",
            2: "Scanner",
            3: "Analyzer"
        }
    
        selected_function_names = [function_map[fn] for fn in selected_functions]
        for function_name in selected_function_names:
            print(f"\n[\033[34m+\u001b[0m] Selected functions - {function_name}:")
            submenu = self.MainMenu[function_name]()
            if submenu:
                self.print_submenu(submenu)
                while True:
                    sub_options_input = input("[\033[36m>\u001b[0m] Enter the numbers of the functions to automate (comma-separated): ")
                    sub_options = [int(x.strip()) for x in sub_options_input.replace(" ", "").split(",") if x.strip()]
                    if all(1 <= sub_option <= len(submenu) for sub_option in sub_options):
                        break
                    else:
                        print(f"[\033[31m!\u001b[0m] Please choose options within the range 1 - {len(submenu)}")
                for sub_option in sub_options:
                    sub_key = list(submenu.keys())[sub_option - 1]
                    FuncTasks[sub_key] = submenu[sub_key]
    
        self.print_submenu(modes)
        while True:
            try:
                mode_input = int(input("\n[\033[36m>\u001b[0m] Select mode for automation: "))
                if 1 <= mode_input <= len(modes):
                    self.selected_mode = list(modes.keys())[mode_input - 1]
                    break
                else:
                    print("[\033[31m!\u001b[0m] Invalid mode selection. Please choose a mode from the list.")
            except ValueError:
                print("[\033[31m!\u001b[0m] Invalid input. Please enter a number.")
    
        print("\n======================= \033[33mSummary\u001b[0m =======================")
        print(f"[\033[33m$\u001b[0m] Selected mode for automation: \033[32m{self.selected_mode}\u001b[0m")
        print(f"[\033[33m$\u001b[0m] Total functions selected for automation: \033[32m{len(FuncTasks)}\u001b[0m")
        print("[\033[33m$\u001b[0m] Selected functions for automation:")
        for name, _ in FuncTasks.items():
            print(f"[\033[34m+\u001b[0m] \033[32m{name}\u001b[0m")
    
        print("\n")
        
        for _, iFunc in FuncTasks.items():
            TaskAutomationFunc.create_task(iFunc)
            
        TaskAutomationFunc.set_mode(self.selected_mode)
        TaskAutomationFunc.run_tasks()
    

    












    def HelpOptions(self):
        try:
            with open("NetGuardian/NetGuardian.txt", "r") as HelpRead:
                print(HelpRead.read())
        except FileNotFoundError:
            print("[\033[31m!\u001b[0m] Help file not found.")
        
  

    












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
    engine = Engine()
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
    
    
    
    
    