from scapy.all import ARP, Ether, srp

def scan_network(ip):
    print(f"Scanning network {ip}...")

    #Arp request to find devices
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    
    #Send the packet and capture the response
    result = srp(packet, timeout=10, verbose=False)[0]

    devices = []
    for sent, recieved in result:
        devices.append({'ip': recieved.psrc,
                        'mac': recieved.hwsrc })

    print("\nDevices Found:")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
         print(f"{device['ip']}\t\t{device['mac']}")


ip_address_to_scan = input("Enter Ip Address:")
scan_network("ip_address_to_scan")