import toga
import psutil
import tracemalloc
import subprocess
import ipaddress
import socket
import asyncio
import platform
import aioping
from toga.style import Pack
from toga.style.pack import COLUMN

class ScanfyApp(toga.App):
    def startup(self):
        self.main_window = toga.MainWindow(title="Scanfy - Network Scanner", size=(300, 400))
        self.interface_dropdown = toga.Selection(on_change=self.interface_selected)
        self.text_label_hostname = toga.Label('Hostname:', style=Pack(padding=5))
        self.text_label_ip_mask = toga.Label('IP Address:', style=Pack(padding=5))
        self.text_label_subnet = toga.Label('Subnet:', style=Pack(padding=5))
        self.scan_button = toga.Button('Scan', on_press=self.execute_scan)
        self.status_label = toga.Label('', style=Pack(padding=5))
        self.detailed_list = toga.DetailedList(['IP Address', 'Status']) # Добавляем DetailedList
        self.detailed_list.data = [] # Инициализируем данные DetailedList пустым списком

        content_box = toga.Box(style=Pack(direction=COLUMN, padding=10))
        content_box.add(self.interface_dropdown)
        content_box.add(self.text_label_hostname)
        content_box.add(self.text_label_ip_mask)
        content_box.add(self.text_label_subnet)
        content_box.add(self.scan_button)
        content_box.add(self.status_label)
        content_box.add(self.detailed_list)

        self.main_window.content = content_box
        self.populate_interface_dropdown()
        self.interface_selected(self.interface_dropdown)
        self.main_window.show()

    def populate_interface_dropdown(self):
        interfaces = []
        system = platform.system()

        if system == "Windows":
            for interface, addrs in psutil.net_if_addrs().items():
                if not interface.startswith("Loopback"):
                    for addr in addrs:
                        if addr.family == socket.AddressFamily.AF_INET:
                            interfaces.append(interface)
                            break
        elif system == "Linux":
            for interface in psutil.net_if_stats().keys():
                if not interface.startswith("lo"):
                    addrs = psutil.net_if_addrs()[interface]
                    for addr in addrs:
                        if addr.family == socket.AddressFamily.AF_INET:
                            interfaces.append(interface)
                            break
        
        self.interface_dropdown.items = interfaces

    def interface_selected(self, widget):
        self.detailed_list.data = []
        selected_interface = widget.value
        if selected_interface:
            hostname = self.get_hostname()
            ip_address = self.get_ip_address(selected_interface)
            subnet_mask = self.get_subnet_mask(selected_interface)
            subnet = self.get_subnet(selected_interface)

            self.text_label_hostname.text = f"Hostname: {hostname}"
            self.text_label_ip_mask.text = f"IP Address: {ip_address}/{subnet_mask}"
            self.text_label_subnet.text = f"Subnet: {subnet}"

    def get_hostname(self): # получаем имя хоста
        try:
            return socket.gethostname()
        except socket.herror:
            return "n/a"

    def get_ip_address(self, interface):
        try:
            return psutil.net_if_addrs()[interface][1].address
        except KeyError:
            return "n/a"

    def get_subnet_mask(self, interface):
        try:
            return psutil.net_if_addrs()[interface][1].netmask
        except KeyError:
            return "n/a"

    def get_subnet(self, interface):
        ip_address = self.get_ip_address(interface)
        try:
            return ipaddress.ip_network(f"{ip_address}/24", strict=False)
        except ValueError:
            return "n/a"

    def update_detailed_list(self, ip_address, status):
        self.detailed_list.data.append((ip_address, status)) # Добавляем новую пару данных в DetailedList

    def execute_scan(self, widget):
        selected_interface = self.interface_dropdown.value
        subnet = self.get_subnet(selected_interface)
        hosts = list(subnet.hosts())

        async def scan(progress_callback):
            async def process_ip(ip_address):
                try:
                    result = await asyncio.create_subprocess_shell(
                        f"ping -n 1 {ip_address}",
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        shell=True
                    )
                    await result.communicate()
                    
                    if result.returncode == 0:
                        status = "Reachable"
                    else:
                        status = "Not reachable"
                        
                except Exception as e:
                    status = "Error: " + str(e)
                    
                await progress_callback(ip_address, status)

            # await asyncio.gather(*[process_ip(str(ip)) for ip in hosts]) #  для параллельного выполнения асинхронных задач
            for ip in hosts:                    # для запуска последовательного
                await process_ip(str(ip))       # синхронного сканирования 

        async def progress_callback(ip_address, status):
            self.update_detailed_list(ip_address, status)

        tracemalloc.start()
        
        if asyncio.get_event_loop().is_running():
            asyncio.get_event_loop().create_task(scan(progress_callback))
        else:
            # asyncio.get_event_loop().run_until_complete(scan(progress_callback)) 
            asyncio.run(scan(progress_callback)) # для запуска асинхронного сканирования 

def main():
    return ScanfyApp()

if __name__ == '__main__':
    main().main_loop()