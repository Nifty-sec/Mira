import asyncio
import psutil
import socket  # Import socket module for connection types
import ctypes
import win32serviceutil
import wmi

def get_all_services():
    """Fetch all services once and return a mapping of PID to service names."""
    services_map = {}
    try:
        c = wmi.WMI()
        for service in c.Win32_Service():
            if service.ProcessId:
                if service.ProcessId not in services_map:
                    services_map[service.ProcessId] = []
                services_map[service.ProcessId].append(service.DisplayName)
    except Exception as e:
        print(f"Error retrieving services: {e}")
    return services_map

async def fetch_services(pid, services_map):
    """Fetch services for a given PID and print results immediately."""
    services_str = ', '.join(services_map.get(pid, [])) if pid in services_map else 'None'
    print(f"svchost.exe PID: {pid} - Services: {services_str}")

async def get_svchost_pids():
    """Fetch PIDs of running 'svchost' processes and their associated services."""
    print("Fetching svchost PIDs and associated services...")
    tasks = []
    
    # Fetch all services once
    services_map = get_all_services()

    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == 'svchost.exe':
            tasks.append(fetch_services(proc.info['pid'], services_map))
    
    await asyncio.gather(*tasks)
    print()  # To add a newline after all output

def get_dlls_for_svchost(pid):
    """Fetch loaded DLLs for a given svchost PID."""
    try:
        proc = psutil.Process(pid)
        dlls = proc.memory_maps()
        dll_names = [dll.path for dll in dlls]
        return dll_names
    except Exception as e:
        print(f"Error retrieving DLLs for PID {pid}: {e}")
        return []

async def fetch_dlls(pid):
    """Fetch DLLs for a given PID and print results immediately."""
    dlls = get_dlls_for_svchost(pid)
    dlls_str = ', '.join(dlls) if dlls else 'None'
    print(f"svchost.exe PID: {pid} - Loaded DLLs: {dlls_str}")

async def get_active_dlls():
    """Fetch loaded DLLs for a specific svchost PID."""
    pid = input("Enter the PID of the svchost.exe process: ")

    try:
        pid = int(pid)  # Convert input to integer
        dlls = get_dlls_for_svchost(pid)
        dlls_str = ', '.join(dlls) if dlls else 'None'
        print(f"svchost.exe PID: {pid} - Loaded DLLs: {dlls_str}")
    except ValueError:
        print("Invalid PID. Please enter a numeric value.")
    except psutil.NoSuchProcess:
        print(f"No process found with PID {pid}.")

def assess_vulnerability(rss, vms, private, num_handles, num_threads):
    """Assess potential vulnerability to process injection based on memory metrics."""
    # Adjusted threshold values
    HIGH_PRIVATE_MEMORY_THRESHOLD = 20  # MB
    HIGH_THREAD_COUNT_THRESHOLD = 15
    HIGH_HANDLE_COUNT_THRESHOLD = 50

    vulnerabilities = []

    if private > HIGH_PRIVATE_MEMORY_THRESHOLD:
        vulnerabilities.append(f"High Private Memory Usage: {private:.2f} MB")

    if num_threads > HIGH_THREAD_COUNT_THRESHOLD:
        vulnerabilities.append(f"High Thread Count: {num_threads}")

    if num_handles > HIGH_HANDLE_COUNT_THRESHOLD:
        vulnerabilities.append(f"High Handle Count: {num_handles}")

    return vulnerabilities

def get_memory_usage():
    """Fetch detailed memory usage for svchost processes and assess vulnerability to injection."""
    total_rss = 0  # Total physical memory used by svchost processes
    total_vms = 0  # Total virtual memory used by svchost processes

    print("Fetching detailed memory usage for svchost.exe processes...")
    print(f"{'PID':<10}{'RSS (MB)':<15}{'VMS (MB)':<15}{'Private (MB)':<15}{'Handles':<10}{'Threads':<10}{'Vulnerabilities'}")
    print("=" * 110)

    for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'memory_percent', 'num_threads']):
        if proc.info['name'] == 'svchost.exe':
            rss = proc.info['memory_info'].rss / 1024 ** 2  # Convert to MB
            vms = proc.info['memory_info'].vms / 1024 ** 2  # Convert to MB
            private = proc.memory_info().private / 1024 ** 2  # Private memory
            num_handles = proc.num_handles() if hasattr(proc, 'num_handles') else "N/A"  # Open handles
            num_threads = proc.info['num_threads']  # Number of threads

            total_rss += rss
            total_vms += vms
            
            # Assess vulnerability
            vulnerabilities = assess_vulnerability(rss, vms, private, num_handles, num_threads)
            vulnerabilities_str = ", ".join(vulnerabilities) if vulnerabilities else "None"

            print(f"{proc.info['pid']:<10}{rss:<15.2f}{vms:<15.2f}{private:<15.2f}{num_handles:<10}{num_threads:<10}{vulnerabilities_str}")

    print("=" * 110)
    print(f"Total Memory Used by svchost.exe - RSS: {total_rss:.2f} MB, VMS: {total_vms:.2f} MB")
    print()

def get_network_connections():
    """Fetch detailed network connections for svchost processes."""
    print("Fetching network connections for svchost.exe processes...")
    print(f"{'PID':<8}{'Type':<8}{'Protocol':<10}{'Local Address':<25}{'Remote Address':<25}{'Status':<15}{'Services'}")
    print("=" * 110)

    services_map = get_all_services()  # Fetch all services once

    for conn in psutil.net_connections(kind='inet'):
        try:
            proc = psutil.Process(conn.pid)
            if proc.name() == 'svchost.exe':
                conn_type = 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                protocol = 'IPv4' if conn.family == socket.AF_INET else 'IPv6'
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                
                # Get services associated with the PID
                services_str = ', '.join(services_map.get(conn.pid, [])) if conn.pid in services_map else 'None'

                print(f"{conn.pid:<8}{conn_type:<8}{protocol:<10}{local_addr:<25}{remote_addr:<25}{conn.status:<15}{services_str}")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    print("=" * 110)

def main():
    while True:
        print("Please choose an option:")
        print("1. Grab PIDs of running svchost services")
        print("2. Grab available running DLLs active on the machine")
        print("3. Show memory usage of svchost services")
        print("4. Show network connections of svchost services")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            asyncio.run(get_svchost_pids())
        elif choice == '2':
            asyncio.run(get_active_dlls())
        elif choice == '3':
            get_memory_usage()
        elif choice == '4':
            get_network_connections()
        elif choice == '5':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")
        print()

if __name__ == "__main__":
    main()
