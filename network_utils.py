
import socket, subprocess, platform

def ping(host):
    param = '-n' if platform.system().lower()=='windows' else '-c'
    cmd = ['ping', param, '1', host]
    try:
        res = subprocess.run(cmd, capture_output=True, timeout=3)
        return res.returncode == 0
    except Exception:
        return False
