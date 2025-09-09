import os
import platform
import subprocess
import json
import socket
import pwd
import grp
import logging

# 設定日誌
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", force=True)

def get_system_info():
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.version(),
        "kernel_version": platform.uname()[2],
        "architecture": platform.architecture()[0]
    }

def run_command(command, timeout=10):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
        return result.stdout.strip() if result.returncode == 0 else f"Error: {result.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error: {e}"

def get_installed_hotfixes():
    return run_command(["dpkg-query", "-l"])

def get_open_ports():
    return run_command(["ss", "-tulnp"])

def get_running_processes():
    return run_command(["ps", "aux"])

def get_running_services():
    return run_command(["systemctl", "list-units", "--type=service", "--state=running"])

def get_users_and_groups():
    try:
        users = [user.pw_name for user in pwd.getpwall() if int(user.pw_uid) >= 1000]
        groups = [group.gr_name for group in grp.getgrall()]
        return {"users": users, "groups": groups}
    except Exception as e:
        logging.error(f"Error retrieving users and groups: {e}")
        return {"users": [], "groups": []}

def get_firewall_status():
    return run_command(["ufw", "status", "verbose"])

def get_disk_partitions():
    return run_command(["lsblk", "-o", "NAME,SIZE,MOUNTPOINT,FSTYPE"])

def get_cve_patches():
    return run_command(["grep", "CVE", "/var/log/dpkg.log"])

def get_kernel_security():
    return run_command(["sysctl", "-a"])

def get_kernel_upgrades():
    return run_command(["apt", "list", "--upgradable"])

def get_installed_software():
    return run_command(["dpkg-query", "-l"])

def get_java_version():
    return run_command(["java", "-version"])

def get_python_packages():
    return run_command(["pip", "list"])

def get_docker_images():
    return run_command(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"])

def get_system_logs():
    return run_command(["journalctl", "-n", "50", "--no-pager"])

def collect_system_data():
    logging.info("Starting system and security data collection...")
    
    system_data = get_system_info()
    system_data.update({
        "installed_hotfixes": get_installed_hotfixes(),
        "open_ports": get_open_ports(),
        "running_processes": get_running_processes(),
        "running_services": get_running_services(),
        "users_and_groups": get_users_and_groups(),
        "firewall_status": get_firewall_status(),
        "disk_partitions": get_disk_partitions(),
        "cve_patches": get_cve_patches(),
        "kernel_security": get_kernel_security(),
        "kernel_upgrades": get_kernel_upgrades(),
        "installed_software": get_installed_software(),
        "java_version": get_java_version(),
        "python_packages": get_python_packages(),
        "docker_images": get_docker_images(),
        "system_logs": get_system_logs()
    })
    
    os.makedirs("data", exist_ok=True)
    output_file = "data/system_info.json"
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(system_data, f, indent=4)
    
    logging.info(f"System and security data collection completed! Data saved to {output_file}")

if __name__ == "__main__":
    collect_system_data()
