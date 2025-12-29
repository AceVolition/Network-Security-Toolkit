import socket
import nmap
import multiprocessing as mp
import time

class PPSSocketClass():
    """
    Class for socket-based port scanning functionality
    """
    
    def __init__(self):
        self.scan_results = []
        self.timeout = 1
        
    def set_timeout(self, timeout_val):
        try:
            self.timeout = float(timeout_val)
            print(f"Timeout set to {self.timeout} seconds")
        except Exception as e:
            print(f"Error setting timeout: {e}")
        
    def read_ips_from_file(self, filename):
        ip_list = []
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                for line in file:
                    ip = line.strip()
                    if ip:
                        ip_list.append(ip)
        except Exception as e:
            print(f"Error reading IP file: {e}")
        return ip_list
        
    def read_ports_from_file(self, filename):
        port_list = []
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                for line in file:
                    port = line.strip()
                    if port:
                        # Manual digit checking using only basic comparisons
                        is_all_digits = True
                        for char in port:
                            # Check if character is between '0' and '9'
                            if not (char >= '0' and char <= '9'):
                                is_all_digits = False
                                break
                        
                        if is_all_digits:
                            port_list.append(int(port))
        except Exception as e:
            print(f"Error reading port file: {e}")
        return port_list
        
    def scan_single_socket(self, ip, port):
        try:
            mysession = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            mysession.settimeout(self.timeout)
            
            if mysession.connect_ex((ip, port)) == 0:
                mysession.close()
                
                current_time = time.time()
                time_struct = time.gmtime(current_time)
                utc_date = f"{time_struct.tm_mday:02d}:{time_struct.tm_mon:02d}:{time_struct.tm_year}"
                utc_time = f"{time_struct.tm_hour:02d}:{time_struct.tm_min:02d}"
                
                # Use IP directly - no getfqdn()
                hostname = ip
                
                port_names = {
                    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
                    80: "http", 110: "pop3", 143: "imap", 443: "https", 
                    587: "submission", 993: "imaps", 995: "pop3s"
                }
                portname = port_names.get(port, "unknown")
                    
                return {
                    'utc_date': utc_date,
                    'utc_time': utc_time,
                    'host_ip': ip,
                    'hostname': hostname,
                    'protocol': 'tcp',
                    'portnum': port,
                    'portname': portname,
                    'reason': 'syn-ack',
                    'product': 'unknown',
                    'version': 'unknown',
                    'cpe': 'unknown',
                    'status': 'open'
                }
            mysession.close()
        except Exception as e:
            print(f"Scan error for {ip}:{port}: {e}")
        return None
        
    def port_scan_sockets_keyboard(self):
        try:
            IPA = input("Enter IP number to scan ")
            PN = int(input("Enter Port number to scan between 1 and 65535 "))
            
            result = self.scan_single_socket(IPA, PN)
            if result:
                self.scan_results.append(result)
                self.display_results([result])
                
            else:
                print(f"IPNum: {IPA}, Port No: {PN} is closed or filtered")
        except Exception as e:
            print(f"Error during keyboard scan: {e}")
            
    def port_scan_sockets_file(self):
        try:
            ip_file = input("Enter IP file name: ")
            port_file = input("Enter port file name: ")
            
            ips = self.read_ips_from_file(ip_file)
            ports = self.read_ports_from_file(port_file)
            
            print(f"Scanning {len(ips)} IPs and {len(ports)} ")
            
            open_count = 0
            for ip in ips:
                for port in ports:
                    result = self.scan_single_socket(ip, port)
                    if result:
                        self.scan_results.append(result)
                        open_count += 1
            
            print(f"Scan completed. Found {open_count} open ports.")
            self.display_results()
                
        except Exception as e:
            print(f"Error during file scan: {e}")
    
    def write_results_to_file(self, filename):
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write("UTC Date;UTC Time;Host IP;Hostname;Protocol;Port;Port Name;Reason;Product;Version;CPE\n")
                for result in self.scan_results:
                    line = f"{result['utc_date']};{result['utc_time']};{result['host_ip']};{result['hostname']};{result['protocol']};{result['portnum']};{result['portname']};{result['reason']};{result['product']};{result['version']};{result['cpe']}\n"
                    file.write(line)
            print(f"Results written to {filename}")
        except Exception as e:
            print(f"Error writing results: {e}")
            
    def display_results(self, results=None):
        if results is None:
            results = self.scan_results
            
        if not results:
            print("No results to display")
            return
            
        print("\n" + "="*120)
        print("SCAN RESULTS")
        print("="*120)
        print(f"{'UTC Date':12} {'UTC Time':8} {'Host IP':15} {'Hostname':30} {'Protocol':8} {'Port':6} {'Port Name':12} {'Reason':10}")
        print("-"*120)
        
        for result in results:
            print(f"{result['utc_date']:12} {result['utc_time']:8} {result['host_ip']:15} {result['hostname'][:28]:30} {result['protocol']:8} {result['portnum']:6} {result['portname']:12} {result['reason']:10}")
        print("="*120)


class PPSSocketConcurrentClass():
    def __init__(self):
        self.scan_results = []
        self.timeout = 1
        
    def set_timeout(self, timeout_val):
        try:
            self.timeout = float(timeout_val)
            print(f"Timeout set to {self.timeout} seconds")
        except Exception as e:
            print(f"Error setting timeout: {e}")
        
    def scan_single_concurrent(self, args):
        ip, port, timeout = args
        try:
            mysession = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            mysession.settimeout(timeout)
            
            if mysession.connect_ex((ip, port)) == 0:
                mysession.close()
                
                current_time = time.time()
                time_struct = time.gmtime(current_time)
                utc_date = f"{time_struct.tm_mday:02d}:{time_struct.tm_mon:02d}:{time_struct.tm_year}"
                utc_time = f"{time_struct.tm_hour:02d}:{time_struct.tm_min:02d}"
                
                # Use IP directly - no getfqdn()
                hostname = ip
                
                port_names = {
                    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
                    80: "http", 110: "pop3", 143: "imap", 443: "https", 
                    587: "submission", 993: "imaps", 995: "pop3s"
                }
                portname = port_names.get(port, "unknown")
                    
                return {
                    'utc_date': utc_date,
                    'utc_time': utc_time,
                    'host_ip': ip,
                    'hostname': hostname,
                    'protocol': 'tcp',
                    'portnum': port,
                    'portname': portname,
                    'reason': 'syn-ack',
                    'product': 'unknown',
                    'version': 'unknown',
                    'cpe': 'unknown',
                    'status': 'open'
                }
            mysession.close()
        except Exception:
            pass
        return None
        
    def port_scan_sockets_concurrent(self):
        try:
            ip_file = input("Enter IP file name: ")
            port_file = input("Enter port file name: ")
            
            socket_reader = PPSSocketClass()
            ips = socket_reader.read_ips_from_file(ip_file)
            ports = socket_reader.read_ports_from_file(port_file)
            
            total_combinations = len(ips) * len(ports)
            print(f"Concurrently scanning {len(ips)} IPs and {len(ports)} ports ({total_combinations} combinations) ")
            
            tasks = [(ip, port, self.timeout) for ip in ips for port in ports]
            print(f"Created task list with {len(tasks)} tasks - all combinations included")
            
            with mp.Pool(8) as pool:
                results = pool.map(self.scan_single_concurrent, tasks)
            
            self.scan_results = [result for result in results if result is not None]
            
            print(f"Concurrent scan completed. Found {len(self.scan_results)} open ports.")
            self.display_results()
            
                
        except Exception as e:
            print(f"Error during concurrent scan: {e}")
    
    def write_results_to_file(self, filename):
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write("UTC Date;UTC Time;Host IP;Hostname;Protocol;Port;Port Name;Reason;Product;Version;CPE\n")
                for result in self.scan_results:
                    line = f"{result['utc_date']};{result['utc_time']};{result['host_ip']};{result['hostname']};{result['protocol']};{result['portnum']};{result['portname']};{result['reason']};{result['product']};{result['version']};{result['cpe']}\n"
                    file.write(line)
            print(f"Results written to {filename}")
        except Exception as e:
            print(f"Error writing results: {e}")
            
    def display_results(self):
        if not self.scan_results:
            print("No results to display")
            return
            
        print("\n" + "="*120)
        print("CONCURRENT SCAN RESULTS")
        print("="*120)
        print(f"{'UTC Date':12} {'UTC Time':8} {'Host IP':15} {'Hostname':30} {'Protocol':8} {'Port':6} {'Port Name':12} {'Reason':10}")
        print("-"*120)
        
        for result in self.scan_results:
            print(f"{result['utc_date']:12} {result['utc_time']:8} {result['host_ip']:15} {result['hostname'][:28]:30} {result['protocol']:8} {result['portnum']:6} {result['portname']:12} {result['reason']:10}")
        print("="*120)


class PSNMapClass():
    def __init__(self):
        self.scan_results = []
        
    def get_scan_type_choice(self):
        scan_types = {
            '1': ('TCP SYN Scan', '-sS'),
            '2': ('UDP Scan', '-sU'), 
            '3': ('FIN Scan', '-sF'),
            '4': ('Xmas Scan', '-sX'),
            '5': ('Ping Scan', '-sn')
        }
        
        print("\nSelect Nmap Scan Type:")
        for key, (name, _) in scan_types.items():
            print(f"{key}. {name}")
        
        while True:
            choice = input("Enter choice (1-5): ")
            if choice in scan_types:
                return scan_types[choice]
            print("Invalid choice. Please enter 1-5.")
    
    def port_scan_nmap_keyboard(self):
        try:
            IPA = input("Enter IP number/CIDR to scan ")
            PN = input("Enter port number/range  ")
            
            scan_name, scan_type = self.get_scan_type_choice()
            
            print(f"Performing {scan_name} on {IPA} ports {PN}...")
            
            NMapObject = nmap.PortScanner()
            scan_args = f'{scan_type} -p {PN} -reason --version-all'
            NMapObject.scan(IPA, arguments=scan_args)
            
            self.process_nmap_results(NMapObject, 'syn-ack')
            self.display_results()
            
        except Exception as e:
            print(f"Nmap scan error: {e}")
            
    def port_scan_nmap_file(self):
        try:
            ip_file = input("Enter IP file name: ")
            port_file = input("Enter port file name: ")
            
            socket_reader = PPSSocketClass()
            ips = socket_reader.read_ips_from_file(ip_file)
            ports = socket_reader.read_ports_from_file(port_file)
            port_range = ','.join(map(str, ports))
            
            scan_name, scan_type = self.get_scan_type_choice()
            
            for ip in ips:
                try:
                    print(f"Scanning {ip} with {scan_name}...")
                    NMapObject = nmap.PortScanner()
                    scan_args = f'{scan_type} -p {port_range} -reason --version-all'
                    NMapObject.scan(ip, arguments=scan_args)
                    self.process_nmap_results(NMapObject, 'syn-ack')
                except Exception as e:
                    print(f"Nmap scan error for {ip}: {e}")
            
            self.display_results()
                
        except Exception as e:
            print(f"Error during nmap file scan: {e}")
    
    def process_nmap_results(self, nmap_scanner, scan_reason):
        try:
            for host in nmap_scanner.all_hosts():
                for proto in nmap_scanner[host].all_protocols():
                    ports = nmap_scanner[host][proto].keys()
                    for port in ports:
                        port_info = nmap_scanner[host][proto][port]
                        
                        current_time = time.time()
                        time_struct = time.gmtime(current_time)
                        utc_date = f"{time_struct.tm_mday:02d}:{time_struct.tm_mon:02d}:{time_struct.tm_year}"
                        utc_time = f"{time_struct.tm_hour:02d}:{time_struct.tm_min:02d}"
                        
                        self.scan_results.append({
                            'utc_date': utc_date,
                            'utc_time': utc_time,
                            'host_ip': host,
                            'hostname': nmap_scanner[host].hostname(),
                            'protocol': proto,
                            'portnum': port,
                            'portname': port_info['name'],
                            'reason': 'syn-ack',
                            'product': port_info.get('product', 'unknown'),
                            'version': port_info.get('version', 'unknown'),
                            'cpe': port_info.get('cpe', 'unknown'),
                            'status': port_info['state']
                        })
        except Exception as e:
            print(f"Error processing nmap results: {e}")
    
    def write_results_to_file(self, filename):
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write("UTC Date;UTC Time;Host IP;Hostname;Protocol;Port;Port Name;Reason;Product;Version;CPE\n")
                for result in self.scan_results:
                    line = f"{result['utc_date']};{result['utc_time']};{result['host_ip']};{result['hostname']};{result['protocol']};{result['portnum']};{result['portname']};{result['reason']};{result['product']};{result['version']};{result['cpe']}\n"
                    file.write(line)
            print(f"Results written to {filename}")
        except Exception as e:
            print(f"Error writing results: {e}")
            
    def display_results(self):
        if not self.scan_results:
            print("No results to display")
            return
            
        print("\n" + "="*120)
        print("NMAP SCAN RESULTS")
        print("="*120)
        print(f"{'UTC Date':12} {'UTC Time':8} {'Host IP':15} {'Hostname':30} {'Protocol':8} {'Port':6} {'Port Name':12} {'Reason':10}")
        print("-"*120)
        
        for result in self.scan_results:
            print(f"{result['utc_date']:12} {result['utc_time']:8} {result['host_ip']:15} {result['hostname'][:28]:30} {result['protocol']:8} {result['portnum']:6} {result['portname']:12} {result['reason']:10}")
        print("="*120)


class PSNMapConcurrentClass():
    def __init__(self):
        self.scan_results = []
        
    def nmap_single_scan(self, args):
        ip, port_range, scan_type, scan_name = args
        try:
            nm = nmap.PortScanner()
            scan_args = f'{scan_type} -p {port_range} -reason --version-all'
            nm.scan(ip, arguments=scan_args)
            
            results = []
            current_time = time.time()
            time_struct = time.gmtime(current_time)
            utc_date = f"{time_struct.tm_mday:02d}:{time_struct.tm_mon:02d}:{time_struct.tm_year}"
            utc_time = f"{time_struct.tm_hour:02d}:{time_struct.tm_min:02d}"
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        port_info = nm[host][proto][port]
                        results.append({
                            'utc_date': utc_date,
                            'utc_time': utc_time,
                            'host_ip': host,
                            'hostname': nm[host].hostname(),
                            'protocol': proto,
                            'portnum': port,
                            'portname': port_info['name'],
                            'reason': 'syn-ack',
                            'product': port_info.get('product', 'unknown'),
                            'version': port_info.get('version', 'unknown'),
                            'cpe': port_info.get('cpe', 'unknown'),
                            'status': port_info['state']
                        })
            return results
        except Exception as e:
            print(f"Nmap scan error for {ip}: {e}")
            return []
        
    def port_scan_nmap_concurrent(self):
        try:
            ip_file = input("Enter IP file name: ")
            port_file = input("Enter port file name: ")
            
            socket_reader = PPSSocketClass()
            ips = socket_reader.read_ips_from_file(ip_file)
            ports = socket_reader.read_ports_from_file(port_file)
            port_range = ','.join(map(str, ports))
            
            scan_name, scan_type = self.get_scan_type_choice()
            
            print(f"Concurrently scanning {len(ips)} IPs with {scan_name}...")
            
            tasks = [(ip, port_range, scan_type, scan_name) for ip in ips]
            
            with mp.Pool(8) as pool:
                results_list = pool.map(self.nmap_single_scan, tasks)
            
            for results in results_list:
                self.scan_results.extend(results)
            
            print(f"Concurrent nmap scan completed. Found {len(self.scan_results)} results.")
            self.display_results()
                
        except Exception as e:
            print(f"Error during concurrent nmap scan: {e}")
    
    def get_scan_type_choice(self):
        return PSNMapClass().get_scan_type_choice()
    
    def write_results_to_file(self, filename):
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write("UTC Date;UTC Time;Host IP;Hostname;Protocol;Port;Port Name;Reason;Product;Version;CPE\n")
                for result in self.scan_results:
                    line = f"{result['utc_date']};{result['utc_time']};{result['host_ip']};{result['hostname']};{result['protocol']};{result['portnum']};{result['portname']};{result['reason']};{result['product']};{result['version']};{result['cpe']}\n"
                    file.write(line)
            print(f"Results written to {filename}")
        except Exception as e:
            print(f"Error writing results: {e}")
            
    def display_results(self):
        if not self.scan_results:
            print("No results to display")
            return
            
        print("\n" + "="*120)
        print("CONCURRENT NMAP RESULTS")
        print("="*120)
        print(f"{'UTC Date':12} {'UTC Time':8} {'Host IP':15} {'Hostname':30} {'Protocol':8} {'Port':6} {'Port Name':12} {'Reason':10}")
        print("-"*120)
        
        for result in self.scan_results:
            print(f"{result['utc_date']:12} {result['utc_time']:8} {result['host_ip']:15} {result['hostname'][:28]:30} {result['protocol']:8} {result['portnum']:6} {result['portname']:12} {result['reason']:10}")
        print("="*120)


# =============================================================================
# MENU SYSTEM
# =============================================================================

def GetMenuChoice(MItems, MenuTitle):
    """
    This functions displays the menu one line at a time and
    allows the user to enter the menu choice and returns the 
    menu choice selected by the user
    """
    ItemNum = 0
    print(f"\n{MenuTitle}:\n")
    for Anitem in MItems:
        ItemNum += 1
        print(f"{ItemNum}.{Anitem}")
    
    while True:
        try:
            ChoiceNum = int(input(f"Enter the integer choice between 1 and {len(MItems)}:"))
            if (ChoiceNum >= 1) and (ChoiceNum <= len(MItems)):
                break
        except ValueError:
            pass
    
    return MItems[ChoiceNum - 1]


def PortScanSockets():
    """
    Port Scan Using Sockets
    """
    scanner = PPSSocketClass()
    
    while True:
        socket_items = ['Scan from Keyboard', 'Scan from Files', 'Set Timeout', 'Return to Network Tools Menu']
        socket_choice = GetMenuChoice(socket_items, 'Socket Scanning Options')
        
        if socket_choice == 'Scan from Keyboard':
            scanner.port_scan_sockets_keyboard()
        elif socket_choice == 'Scan from Files':
            scanner.port_scan_sockets_file()
        elif socket_choice == 'Set Timeout':
            timeout = input("Enter timeout in seconds: ")
            scanner.set_timeout(timeout)
        else:
            break


def PortScanNMap():
    """
    Port Scan Using NMap
    """
    scanner = PSNMapClass()
    
    while True:
        nmap_items = ['Scan from Keyboard', 'Scan from Files', 'Return to Network Tools Menu']
        nmap_choice = GetMenuChoice(nmap_items, 'NMap Scanning Options')
        
        if nmap_choice == 'Scan from Keyboard':
            scanner.port_scan_nmap_keyboard()
        elif nmap_choice == 'Scan from Files':
            scanner.port_scan_nmap_file()
        else:
            break


def PortScanSocketsConcurrent():
    """
    Concurrent Socket Scanning
    """
    scanner = PPSSocketConcurrentClass()
    
    while True:
        socket_items = ['Concurrent Scan from Files', 'Set Timeout', 'Return to Network Tools Menu']
        socket_choice = GetMenuChoice(socket_items, 'Concurrent Socket Scanning Options')
        
        if socket_choice == 'Concurrent Scan from Files':
            scanner.port_scan_sockets_concurrent()
        elif socket_choice == 'Set Timeout':
            timeout = input("Enter timeout in seconds: ")
            scanner.set_timeout(timeout)
        else:
            break


def PortScanNMapConcurrent():
    """
    Concurrent NMap Scanning
    """
    scanner = PSNMapConcurrentClass()
    scanner.port_scan_nmap_concurrent()


def ProcessNetworkToolsChoice(Choice):
    """
    Process network tools menu choice
    """
    if Choice == 'Port Scan Using Sockets':
        PortScanSockets()
    elif Choice == 'Port Scan Using Sockets Concurrent':
        PortScanSocketsConcurrent()
    elif Choice == 'Port Scan Using NMap':
        PortScanNMap()
    elif Choice == 'Port Scan Using NMap Concurrent':
        PortScanNMapConcurrent()
    else:
        print(f"Choice error in Network Tools Menu")


def GetNetworkToolsChoice():
    """
    Network Tools Menu
    """
    while True:
        NetworkToolsItems = [
            'Port Scan Using Sockets',
            'Port Scan Using Sockets Concurrent', 
            'Port Scan Using NMap',
            'Port Scan Using NMap Concurrent',
            'Return to Main Menu'
        ]
        NetworkToolsTitle = 'Network Tools Menu'
        NetworkToolsChoice = GetMenuChoice(NetworkToolsItems, NetworkToolsTitle)
        print(f'Network Tools Choice is: {NetworkToolsChoice}')
        
        if NetworkToolsChoice != 'Return to Main Menu':        
            ProcessNetworkToolsChoice(NetworkToolsChoice)
        else:
            break


def ProcessMainMenuChoice(Choice):
    """
    Process main menu choice
    """
    if Choice == 'Network Tools':
        GetNetworkToolsChoice()
    else:
        print(f"Choice error in Main Menu")


def GetMainMenuChoice():
    """
    Main Menu
    """
    while True:
        MainmenuItems = ['Network Tools', 'Quit Program']
        MainmenuTitle = 'Toolkit Main Menu'
        MainMenuChoice = GetMenuChoice(MainmenuItems, MainmenuTitle)
        print(f'Main Menu Choice is: {MainMenuChoice}')
        
        if MainMenuChoice != 'Quit Program':        
            ProcessMainMenuChoice(MainMenuChoice)
        else:
            print(f"Bye")
            break


def main():
    """
    Main function
    """
    GetMainMenuChoice()


if __name__ == "__main__":
    main()