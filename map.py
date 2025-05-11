from scapy.all import ARP, Ether, IP, srp
import json
import time
import sys

__DEFAULT_VERBOSE = 1

_fullff = 'ff:ff:ff:ff:ff:ff'

_DEFAULT_FILE = 'homebox_map_data.json'
_HOME_BASE = '192.168.178.'
_HOME_RANGE = _HOME_BASE + '0/24'
_PREFERRED_GATEWAY = _HOME_BASE + '1'
_BACKUP_GATEWAY = '192.168.0.1'
_MAIN_LIST = "fav_devices"

if __DEFAULT_VERBOSE:
    print("Module has been hard-coded to be verbose. You can change this by setting __DEFAULT_VERBOSE to 0.")
    print(f"Call help({__name__}) for all functions.")

def send_ARP(ip, timeout=2, verbose=__DEFAULT_VERBOSE):
    if verbose:
        print(f"Sending ARP request to {ip}")
    arp = ARP(pdst=ip)
    ether = Ether(dst=_fullff)
    packet = ether / arp

    # Send the packet and receive the response
    result = srp(packet, timeout=timeout, verbose=verbose)[0]

    # Check if we received a response
    if verbose:
        if result:
            print(f"Received response from {ip}")
        else:
            print(f"No response from {ip}")
    return result

def test_gateway(gateway=_PREFERRED_GATEWAY, verbose=__DEFAULT_VERBOSE):
    if verbose:
        print(f"Testing gateway: {gateway}")

    # Send ARP request to the gateway
    result = send_ARP(gateway, timeout=5, verbose=verbose)

    # Check if we received a response
    if verbose:
        if result:
            print(f"Gateway {gateway} is reachable.")
        else:
            print(f"Gateway {gateway} is not reachable.")
    return result

def test_all_gateways(gateways=(_PREFERRED_GATEWAY, _BACKUP_GATEWAY), verbose=__DEFAULT_VERBOSE):
    for gateway in gateways:
        if test_gateway(gateway, verbose):
            if verbose:
                print(f"Gateway {gateway} is reachable.")
            return gateway
    print(f"None of the gateways {gateways} are reachable.")

def find_all_devices(iprange=_HOME_RANGE, timeout=2, verbose=__DEFAULT_VERBOSE):
    if verbose:
        print(f"Scanning IP range: {iprange}")

    # Send ARP request to the entire IP range
    result = send_ARP(iprange, timeout=timeout, verbose=verbose)

    # Check if we received a response
    if verbose:
        print(f'Found {len(result)} devices in the range {iprange}')


    devices = [(d.psrc,d.hwsrc) for c, d in result]

    if verbose > 1:
        for ip, mac in sorted(devices,key=lambda x: int(x[0].split('.')[-1])):
            print(f"{mac} {ip}")

    return devices

def match_ip_in_devices(ip, devices):
    for d in devices:
        if d[0] == ip:
            return d
    return None

def match_mac_in_devices(mac, devices):
    for d in devices:
        if d[1] == mac:
            return d
    return None

def match_in_devices(ip, mac, devices, verbose=__DEFAULT_VERBOSE):
    """
    Check if a device with the given IP and MAC address is in the list of devices.

    :param ip: IP address to check
    :param mac: MAC address to check
    :param devices: List of devices to check against
    :param verbose: If True, print additional information
    :return: 0 if not found, 1 if IP changed, 2 if MAC changed, 3 if conflict, 4 if fully matching
    """
    for d in devices:
        if d[0] == ip and d[1] == mac:
            if verbose:
                print(f"Found device with fully matching IP {ip} and MAC {mac}")
            return 4

    mid = match_ip_in_devices(ip, devices)
    mmd = match_mac_in_devices(mac, devices)
    if mid is not None and mmd is not None:
        if verbose:
            print(f"Found conflicting devices: IP match has MAC {mid[1]} and MAC match has IP {mmd[0]}")
        return 3
    elif mid is not None:
        if verbose:
            print(f"Found device with partially matching IP {ip}")
        return 2
    elif mmd is not None:
        if verbose:
            print(f"Found device with partially matching MAC {mac}")
        return 1
    return 0

def save(key, value, file=_DEFAULT_FILE):
    try:
        with open(file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}

    data[key] = value

    with open(file, 'w') as f:
        json.dump(data, f)

def load(key=None, file=_DEFAULT_FILE):
    if key is None:
        # load all
        try:
            with open(file, 'r') as f:
                data = json.load(f)
            return data
        except FileNotFoundError:
            return {}
    try:
        with open(file, 'r') as f:
            data = json.load(f)

        if key in data:
            return data[key]
        else:
            return None
    except FileNotFoundError:
        return None

def parse_unix(timestamp):
    """
    Convert a Unix timestamp to a human-readable date and time string.
    """
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

def load_favourites(key=_MAIN_LIST, file=_DEFAULT_FILE, verbose=__DEFAULT_VERBOSE):
    """
    Load the list of favourite devices from the JSON file.
    """
    favourites = load(key, file)
    if favourites is None:
        if verbose:
            print(f"No favourites found in {file} with key {key}")
        return []
    else:
        if verbose:
            print(f"Favourites successfully loaded from {file} with key {key}:")
            for name, (ip, mac), lastonline in favourites:
                print(f"{name} (last: {parse_unix(lastonline)}) is at (IP: {ip[0]}, MAC: {ip[1]})")
        return favourites

def test_favourites(favourites=None, devices=None, now=None, timeout=2, verbose=__DEFAULT_VERBOSE):
    if now is None:
        now = time.time()
    if favourites is None:
        favourites = load_favourites(key=_MAIN_LIST, file=_DEFAULT_FILE, verbose=verbose>1)
    if devices is None:
        devices = find_all_devices(timeout=timeout, verbose=verbose>1)

    if verbose:
        print(f"Testing favourites: {favourites}")

    online = []
    new_favourites = []
    print()
    for fav in favourites: # (name, (ip, mac), lastonline)
        print()
        name = fav[0]
        ip = fav[1][0]
        mac = fav[1][1]
        lastonline = fav[2] if len(fav) > 2 else 0
        mid = match_in_devices(ip, mac, devices, verbose=verbose>1)

        if mid == 0:
            result = send_ARP(ip, timeout=timeout, verbose=verbose>1)
            if result:
                if verbose:
                    print(f"Device was found on second try:")
                mid=4
            else:
                if verbose:
                    print(f"X {name} ({parse_unix(lastonline)}) offline")
                new_favourites.append(fav)
        if mid == 1:
            newmac = match_ip_in_devices(ip, devices)[1]
            if verbose:
                print(f"X Device {name} (last: {parse_unix(lastonline)}) not online or MAC changed, IP {ip} has MAC {newmac}")
                print("Favourites entry won't be updated")
            new_favourites.append(fav)
        elif mid == 2:
            newip = match_mac_in_devices(mac, devices)[0]
            if verbose:
                print(f"! Device {name} (last: {parse_unix(lastonline)}) IP changed, MAC {mac} has IP {newip}")
            online.append((name, (newip, mac), lastonline))
            new_favourites.append((name, (newip, mac), now))
        elif mid == 3:
            newip = match_mac_in_devices(mac, devices)[0]
            newmac = match_ip_in_devices(ip, devices)[1]
            if verbose:
                print(f"! Device {name} (last: {parse_unix(lastonline)}) conflict, IP {ip} has MAC {newmac} and MAC {mac} has IP {newip}")
            # Trust MAC over IP
            online.append((name, (newip, mac), lastonline))
            new_favourites.append((name, (newip, mac), now))
            new_favourites.append((name+'_CONFLICT_OLDIP_NEWMAC', (ip, newmac), now))
        elif mid == 4:
            if verbose:
                print(f"! {name} ({parse_unix(lastonline)}) online\n\t(IP: {ip}, MAC {mac})")
            online.append(fav)
            new_favourites.append((name, (ip, mac), now))
        #else:
        #    new_favourites.append(fav)

    save(_MAIN_LIST, new_favourites)
    return online

def save_favourite(name, ip, mac=None, lastonline=None, key=_MAIN_LIST, file=_DEFAULT_FILE, devices=None, verbose=__DEFAULT_VERBOSE):
    if lastonline is None:
        lastonline = time.time()
    favourites = load_favourites(key, file, verbose=verbose)
    if mac is None:
        if verbose:
            print(f"MAC address not given, searching for it...")
        if devices is None:
            if verbose:
                print("No devices given, ARPing MAC...")
            mac = send_ARP(ip, verbose=verbose)[0][1].hwsrc
        else:
            mac = match_ip_in_devices(ip, devices)[1]
        if mac is None:
            print(f"MAC address not found for IP {ip}")
            return False

    oldsize = len(favourites)
    favourites = [f for f in favourites if f[0] != name]
    if len(favourites) != oldsize:
        if verbose:
            print(f"Found {oldsize - len(favourites)} old entries with name {name}, overwriting them.")


    if verbose:
        print(f"Saving favourite: {name} (last: {parse_unix(lastonline)}) with IP {ip} and MAC {mac}")
    favourites.append((name, (ip, mac), lastonline))

    save(key, favourites, file)
    return True

def delete_favourite(name, key=_MAIN_LIST, file=_DEFAULT_FILE, verbose=__DEFAULT_VERBOSE):
    favourites = load_favourites(key, file, verbose=verbose)
    if not favourites:
        if verbose:
            print(f"No favourites found at all, none to delete.")
        return False
    else:
        if verbose:
            print(f"Deleting all favourites with name: {name} (# found: {len([f for f in favourites if f[0] == name])})")
        new_favourites = [f for f in favourites if f[0] != name]
        save(key, new_favourites, file)
        return True

def backup_file(file=_DEFAULT_FILE, new_backup_file=None, verbose=__DEFAULT_VERBOSE):
    if new_backup_file is None:
        yyyymmddhhmmss = time.strftime('%Y%m%d%H%M%S')
        new_backup_file = file + '.' + yyyymmddhhmmss + '.bak'
    try:
        with open(file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        if verbose:
            print(f"File {file} not found, nothing to backup.")
        return False

    with open(new_backup_file, 'w') as f:
        json.dump(data, f)
    if verbose:
        print(f"Backup of {file} saved to {new_backup_file}")
    return True

if __name__ == '__main__':
    if not test_gateway(_PREFERRED_GATEWAY, verbose=0):
        if test_all_gateways(verbose=1):
            print("Wrong gateway.")
            sys.exit(1)
        else:
            print("No gateway reachable.")
            sys.exit(2)

    m = test_favourites()
    print()
    if not __DEFAULT_VERBOSE: # Don't double print if verbose
        print("Online devices:")
        for f in m:
            print(f'{f[0]} (last: {parse_unix(f[2])}) is at (IP: {f[1][0]}, MAC: {f[1][1]})')

