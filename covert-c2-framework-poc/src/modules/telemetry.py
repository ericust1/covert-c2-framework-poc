import os
import platform
import random
import socket
import time

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class TelemetryCollector:
    def collect_system_info(self):
        info = {
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "arch": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
            "timestamp": time.time(),
        }
        try:
            info["username"] = os.getlogin()
        except Exception:
            info["username"] = os.environ.get("USER", "unknown")

        try:
            info["ip_address"] = socket.gethostbyname(socket.gethostname())
        except Exception:
            info["ip_address"] = "127.0.0.1"

        if HAS_PSUTIL:
            info["process_list"] = self._get_top_processes(10)
            info["network_interfaces"] = self._get_network_interfaces()
            info["disk_usage"] = self._get_disk_usage()

        return info

    def collect_network_connections(self):
        connections = []
        if not HAS_PSUTIL:
            return self._parse_proc_net_tcp()

        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "ESTABLISHED":
                    entry = {
                        "local_addr": str(conn.laddr.ip) + ":" + str(conn.laddr.port),
                        "remote_addr": "",
                        "status": conn.status,
                        "pid": conn.pid,
                    }
                    if conn.raddr:
                        entry["remote_addr"] = str(conn.raddr.ip) + ":" + str(conn.raddr.port)
                    connections.append(entry)
        except (psutil.AccessDenied, PermissionError):
            connections = self._parse_proc_net_tcp()
        except Exception:
            pass

        return connections[:50]

    def _get_top_processes(self, count=10):
        processes = []
        try:
            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                try:
                    info = proc.info
                    processes.append(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            processes.sort(key=lambda p: p.get("cpu_percent", 0) or 0, reverse=True)
        except Exception:
            pass
        return processes[:count]

    def _get_network_interfaces(self):
        interfaces = {}
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            for name in addrs:
                interfaces[name] = {
                    "addresses": [],
                    "up": stats[name].isup if name in stats else None,
                }
                for addr in addrs[name]:
                    interfaces[name]["addresses"].append({
                        "family": addr.family.name,
                        "address": addr.address,
                        "netmask": addr.netmask,
                    }
                )
        except Exception:
            pass
        return interfaces

    def _get_disk_usage(self):
        disks = []
        try:
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disks.append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "total_bytes": usage.total,
                        "used_bytes": usage.used,
                        "free_bytes": usage.free,
                        "percent": usage.percent,
                    })
                except (psutil.AccessDenied, PermissionError, OSError):
                    continue
        except Exception:
            pass
        return disks

    def _parse_proc_net_tcp(self):
        connections = []
        try:
            with open("/proc/net/tcp", "r") as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) < 4:
                        continue
                    state = int(parts[3], 16)
                    if state == 1:
                        local = self._hex_to_ip_port(parts[1])
                        remote = self._hex_to_ip_port(parts[2])
                        connections.append({
                            "local_addr": local,
                            "remote_addr": remote,
                            "status": "ESTABLISHED",
                            "pid": "-",
                        })
        except (FileNotFoundError, PermissionError, OSError):
            pass
        return connections

    def _hex_to_ip_port(self, hex_str):
        try:
            ip_hex, port_hex = hex_str.split(":")
            ip_int = int(ip_hex, 16)
            port = int(port_hex, 16)
            ip = "{}.{}.{}.{}".format(
                (ip_int >> 24) & 0xFF,
                (ip_int >> 16) & 0xFF,
                (ip_int >> 8) & 0xFF,
                ip_int & 0xFF,
            )
            return "{}:{}".format(ip, port)
        except Exception:
            return "0.0.0.0:0"

    def format_beacon(self, telemetry_data):
        return {
            "type": "telemetry",
            "data": telemetry_data,
            "timestamp": time.time(),
        }

    def calculate_beacon_jitter(self, base_interval, jitter_percent):
        jitter = base_interval * jitter_percent
        return max(1.0, base_interval + random.uniform(-jitter, jitter))
