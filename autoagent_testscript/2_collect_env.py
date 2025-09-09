import platform
import subprocess
import json
import socket
import winreg

# Define system information dictionary
system_info = {
    "hostname": socket.gethostname(),
    "os": platform.system(),
    "os_version": platform.version(),
    "architecture": platform.architecture()[0],
}

# Get installed Hotfixes (patches)
def get_hotfixes():
    hotfixes = []
    try:
        result = subprocess.run(["wmic", "qfe", "list", "full"], capture_output=True, text=True)
        for line in result.stdout.split("\n"):
            if "HotFixID" in line:
                hotfixes.append(line.split("=")[-1].strip())
    except Exception as e:
        print(f"Error: {e}")
    return hotfixes

system_info["hotfixes"] = get_hotfixes()

# Get open ports
def get_open_ports():
    try:
        result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error: {e}")
        return None

system_info["open_ports"] = get_open_ports()

# Get running processes
def get_running_processes():
    try:
        result = subprocess.run(["tasklist"], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error: {e}")
        return None

system_info["running_processes"] = get_running_processes()

# Get Windows registry security settings
def get_registry_settings():
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") as key:
            smb1 = winreg.QueryValueEx(key, "SMB1")[0]
        return {"SMB1_Enabled": smb1}
    except FileNotFoundError:
        return {"SMB1_Enabled": "Not Found"}
    except Exception as e:
        print(f"Error: {e}")
        return None

system_info["registry_settings"] = get_registry_settings()

# Get user and group information
def get_users_and_groups():
    try:
        result = subprocess.run(["net", "user"], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error: {e}")
        return None

system_info["users_and_groups"] = get_users_and_groups()

# Get enabled Windows features (e.g., RDP)
def get_windows_features():
    try:
        result = subprocess.run(["dism", "/online", "/get-features"], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error: {e}")
        return None

system_info["windows_features"] = get_windows_features()

# Get disk partition information
def get_disk_partitions():
    try:
        result = subprocess.run(["wmic", "logicaldisk", "get", "name,size,freespace"], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error: {e}")
        return None

system_info["disk_partitions"] = get_disk_partitions()

# Get firewall status
def get_firewall_status():
    try:
        result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error: {e}")
        return None

system_info["firewall_status"] = get_firewall_status()

# Get antivirus status
def get_antivirus_status():
    try:
        result = subprocess.run(["wmic", "/namespace:\\\\root\\SecurityCenter2", "path", "AntivirusProduct", "get", "displayName,state"], capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        print(f"Error: {e}")
        return None

system_info["antivirus_status"] = get_antivirus_status()

# Save system information
with open("data/system_info.json", "w", encoding="utf-8") as f:
    json.dump(system_info, f, indent=4)

print("Environment data collection completed!")
