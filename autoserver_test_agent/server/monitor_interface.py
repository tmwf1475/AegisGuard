import psutil, platform, subprocess

def get_cpu_info():
    return psutil.cpu_percent(interval=1)

def get_memory_info():
    return psutil.virtual_memory().percent

def get_running_services():
    return [proc.info for proc in psutil.process_iter(['pid', 'name'])]

def get_syslog_tail():
    result = subprocess.getoutput("tail -n 30 /var/log/syslog")
    return result.splitlines()

def collect_full_context():
    return {
        "os": platform.platform(),
        "cpu_usage": get_cpu_info(),
        "memory_usage": get_memory_info(),
        "services": get_running_services(),
        "logs": get_syslog_tail()
    }