"""
PREVENT-X Security Testing Lab Health Verification Utility
Validates all 7 core platform services, connectivity, and virtual patch enforcement.
Outputs an aligned PASS/FAIL status table and returns proper exit codes.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import sys
import time

# Ensure project root is on sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import httpx
import redis
import psycopg2


# ANSI Terminal Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def format_status(passed: bool) -> str:
    if passed:
        return f"{GREEN}[PASS]{RESET}"
    return f"{RED}[FAIL]{RESET}"


def check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def test_postgresql() -> dict:
    start = time.perf_counter()
    port = 54320
    is_open = check_port("127.0.0.1", port)
    if not is_open:
        return {
            "name": "PostgreSQL Database",
            "target": f"127.0.0.1:{port}",
            "passed": False,
            "latency_ms": 0.0,
            "details": f"Port {port} not listening",
        }

    try:
        conn = psycopg2.connect(
            "postgresql://preventx_user:preventx_secure_pass@localhost:54320/preventx_db",
            connect_timeout=3,
        )
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        cur.execute("SELECT count(*) FROM users")
        user_count = cur.fetchone()[0]
        conn.close()
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "name": "PostgreSQL Database",
            "target": f"127.0.0.1:{port}",
            "passed": True,
            "latency_ms": round(latency, 1),
            "details": f"SQL query OK (users: {user_count})",
        }
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "name": "PostgreSQL Database",
            "target": f"127.0.0.1:{port}",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": f"Connection error: {str(e)[:45]}",
        }


def test_redis() -> dict:
    start = time.perf_counter()
    port = 6379
    is_open = check_port("127.0.0.1", port)
    if not is_open:
        return {
            "name": "Redis Cache & Broker",
            "target": f"127.0.0.1:{port}",
            "passed": False,
            "latency_ms": 0.0,
            "details": f"Port {port} not listening",
        }

    try:
        r = redis.Redis.from_url("redis://localhost:6379/0", socket_timeout=2)
        pong = r.ping()
        latency = (time.perf_counter() - start) * 1000.0
        if pong:
            return {
                "name": "Redis Cache & Broker",
                "target": f"127.0.0.1:{port}",
                "passed": True,
                "latency_ms": round(latency, 1),
                "details": "PONG received (broker operational)",
            }
        return {
            "name": "Redis Cache & Broker",
            "target": f"127.0.0.1:{port}",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": "Unexpected ping response",
        }
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "name": "Redis Cache & Broker",
            "target": f"127.0.0.1:{port}",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": f"Redis error: {str(e)[:45]}",
        }


def test_backend_health() -> dict:
    start = time.perf_counter()
    url = "http://127.0.0.1:8002/api/v1/health"
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(url)
            latency = (time.perf_counter() - start) * 1000.0
            if resp.status_code == 200:
                data = resp.json()
                status_val = data.get("status")
                version = data.get("version", "1.0.0")
                if status_val == "HEALTHY":
                    return {
                        "name": "FastAPI Backend (Health)",
                        "target": "127.0.0.1:8002/api/v1/health",
                        "passed": True,
                        "latency_ms": round(latency, 1),
                        "details": f"status: HEALTHY (v{version})",
                    }
            return {
                "name": "FastAPI Backend (Health)",
                "target": "127.0.0.1:8002/api/v1/health",
                "passed": False,
                "latency_ms": round(latency, 1),
                "details": f"HTTP {resp.status_code}: {resp.text[:40]}",
            }
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "name": "FastAPI Backend (Health)",
            "target": "127.0.0.1:8002/api/v1/health",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": f"Unreachable: {str(e)[:45]}",
        }


def test_backend_ready() -> dict:
    start = time.perf_counter()
    url = "http://127.0.0.1:8002/api/v1/ready"
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(url)
            latency = (time.perf_counter() - start) * 1000.0
            if resp.status_code == 200:
                data = resp.json()
                db_st = data.get("database", {}).get("status", "UNKNOWN")
                redis_st = data.get("redis", {}).get("status", "UNKNOWN")
                if data.get("ready") is True:
                    return {
                        "name": "FastAPI Backend (Ready)",
                        "target": "127.0.0.1:8002/api/v1/ready",
                        "passed": True,
                        "latency_ms": round(latency, 1),
                        "details": f"database: {db_st}, redis: {redis_st}",
                    }
            return {
                "name": "FastAPI Backend (Ready)",
                "target": "127.0.0.1:8002/api/v1/ready",
                "passed": False,
                "latency_ms": round(latency, 1),
                "details": f"HTTP {resp.status_code} - not ready",
            }
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "name": "FastAPI Backend (Ready)",
            "target": "127.0.0.1:8002/api/v1/ready",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": f"Unreachable: {str(e)[:45]}",
        }


def test_celery_worker() -> dict:
    start = time.perf_counter()
    try:
        from backend.app.workers.celery_app import celery_app
        ping_res = celery_app.control.ping(timeout=2.0)
        latency = (time.perf_counter() - start) * 1000.0
        if ping_res and isinstance(ping_res, list) and len(ping_res) > 0:
            worker_info = ping_res[0]
            worker_name = list(worker_info.keys())[0] if worker_info else "active"
            return {
                "name": "Celery Background Worker",
                "target": "redis://localhost:6379/1",
                "passed": True,
                "latency_ms": round(latency, 1),
                "details": f"Worker active ({worker_name[:25]})",
            }
        return {
            "name": "Celery Background Worker",
            "target": "redis://localhost:6379/1",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": "No response to celery control ping",
        }
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "name": "Celery Background Worker",
            "target": "redis://localhost:6379/1",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": f"Worker ping failed: {str(e)[:40]}",
        }


def test_upstream_app() -> dict:
    start = time.perf_counter()
    url = "http://127.0.0.1:8086/health"
    try:
        with httpx.Client(timeout=2.0) as client:
            resp = client.get(url)
            latency = (time.perf_counter() - start) * 1000.0
            if resp.status_code == 200:
                data = resp.json()
                service = data.get("service", "Upstream App")
                return {
                    "name": "Upstream Test App",
                    "target": "127.0.0.1:8086/health",
                    "passed": True,
                    "latency_ms": round(latency, 1),
                    "details": f"HTTP 200 OK ({service[:25]})",
                }
            return {
                "name": "Upstream Test App",
                "target": "127.0.0.1:8086/health",
                "passed": False,
                "latency_ms": round(latency, 1),
                "details": f"HTTP {resp.status_code}",
            }
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "name": "Upstream Test App",
            "target": "127.0.0.1:8086/health",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": f"Unreachable: {str(e)[:40]}",
        }


def test_nginx_proxy() -> dict:
    start = time.perf_counter()
    port = 8085
    is_open = check_port("127.0.0.1", port)
    if not is_open:
        return {
            "name": "Nginx Virtual Patch Proxy",
            "target": f"127.0.0.1:{port}",
            "passed": False,
            "latency_ms": 0.0,
            "details": f"Port {port} not listening",
        }

    url = f"http://127.0.0.1:{port}/"
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(url)
            latency = (time.perf_counter() - start) * 1000.0
            server_header = resp.headers.get("Server", "nginx")
            waf_header = resp.headers.get("X-WAF-Engine", "")
            return {
                "name": "Nginx Virtual Patch Proxy",
                "target": f"127.0.0.1:{port}/",
                "passed": True,
                "latency_ms": round(latency, 1),
                "details": f"HTTP {resp.status_code} ({server_header}, {waf_header[:15]})",
            }
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "name": "Nginx Virtual Patch Proxy",
            "target": f"127.0.0.1:{port}/",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": f"Proxy request failed: {str(e)[:40]}",
        }


def test_nginx_to_upstream() -> dict:
    start = time.perf_counter()
    url = "http://127.0.0.1:8085/api/v1/checkout?item=1001&qty=1"
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(url)
            latency = (time.perf_counter() - start) * 1000.0
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") in ("PROCESSED", "UPSTREAM_OK"):
                    return {
                        "name": "Nginx-to-Upstream Transit",
                        "target": "127.0.0.1:8085 -> :8086",
                        "passed": True,
                        "latency_ms": round(latency, 1),
                        "details": "Traffic forwarded to upstream successfully",
                    }
            return {
                "name": "Nginx-to-Upstream Transit",
                "target": "127.0.0.1:8085 -> :8086",
                "passed": False,
                "latency_ms": round(latency, 1),
                "details": f"HTTP {resp.status_code} - unexpected response",
            }
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "name": "Nginx-to-Upstream Transit",
            "target": "127.0.0.1:8085 -> :8086",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": f"Upstream communication error: {str(e)[:35]}",
        }


def test_virtual_patch_enforcement() -> dict:
    start = time.perf_counter()
    # Test request with SQL Injection signature: UNION SELECT
    url = "http://127.0.0.1:8085/api/v1/checkout?item=1001'+UNION+SELECT+1,2,3--"
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(url)
            latency = (time.perf_counter() - start) * 1000.0
            waf_blocked = resp.headers.get("X-WAF-Blocked")
            attack_type = resp.headers.get("X-WAF-Attack-Type")
            if resp.status_code == 403 and waf_blocked == "1":
                return {
                    "name": "Virtual Patch Enforcement",
                    "target": "127.0.0.1:8085 (SQLi Test)",
                    "passed": True,
                    "latency_ms": round(latency, 1),
                    "details": f"HTTP 403 Blocked (Attack: {attack_type})",
                }
            return {
                "name": "Virtual Patch Enforcement",
                "target": "127.0.0.1:8085 (SQLi Test)",
                "passed": False,
                "latency_ms": round(latency, 1),
                "details": f"Expected 403, got {resp.status_code}",
            }
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "name": "Virtual Patch Enforcement",
            "target": "127.0.0.1:8085 (SQLi Test)",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": f"Connection failed: {str(e)[:40]}",
        }


def test_frontend() -> dict:
    start = time.perf_counter()
    url = "http://localhost:5173/"
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(url)
            latency = (time.perf_counter() - start) * 1000.0
            if resp.status_code == 200 and ("Vite" in resp.text or "<div id=\"root\">" in resp.text):
                return {
                    "name": "React Frontend UI",
                    "target": "localhost:5173/",
                    "passed": True,
                    "latency_ms": round(latency, 1),
                    "details": "HTTP 200 OK (Vite SPA Ready)",
                }
            return {
                "name": "React Frontend UI",
                "target": "localhost:5173/",
                "passed": False,
                "latency_ms": round(latency, 1),
                "details": f"HTTP {resp.status_code} - unexpected HTML",
            }
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "name": "React Frontend UI",
            "target": "localhost:5173/",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": f"Unreachable: {str(e)[:40]}",
        }


def get_local_network_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def test_network_access() -> dict:
    start = time.perf_counter()
    net_ip = get_local_network_ip()
    if net_ip in ("127.0.0.1", "localhost"):
        return {
            "name": "Network/Wi-Fi Access",
            "target": f"{net_ip}:8002",
            "passed": True,
            "latency_ms": 0.0,
            "details": "Loopback-only environment detected",
        }
    url = f"http://{net_ip}:8002/api/v1/health"
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(url)
            latency = (time.perf_counter() - start) * 1000.0
            if resp.status_code == 200:
                return {
                    "name": "Network/Wi-Fi Access",
                    "target": f"{net_ip}:8002",
                    "passed": True,
                    "latency_ms": round(latency, 1),
                    "details": f"Reachable via Wi-Fi/LAN ({net_ip})",
                }
            return {
                "name": "Network/Wi-Fi Access",
                "target": f"{net_ip}:8002",
                "passed": False,
                "latency_ms": round(latency, 1),
                "details": f"HTTP {resp.status_code} on network IP",
            }
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000.0
        return {
            "name": "Network/Wi-Fi Access",
            "target": f"{net_ip}:8002",
            "passed": False,
            "latency_ms": round(latency, 1),
            "details": f"Unreachable on Wi-Fi: {str(e)[:35]}",
        }


def run_all_checks() -> list:
    checks = [
        test_postgresql(),
        test_redis(),
        test_backend_health(),
        test_backend_ready(),
        test_celery_worker(),
        test_upstream_app(),
        test_nginx_proxy(),
        test_nginx_to_upstream(),
        test_virtual_patch_enforcement(),
        test_frontend(),
        test_network_access(),
    ]
    return checks


def print_table(results: list) -> bool:
    print(f"\n{BOLD}{CYAN}===================================================================================================={RESET}")
    print(f"{BOLD}{CYAN}                      PREVENT-X SECURITY TESTING LAB HEALTH VERIFICATION                     {RESET}")
    print(f"{BOLD}{CYAN}===================================================================================================={RESET}")
    header = f"{BOLD}{'Service':<28} {'Port / Target':<28} {'Status':<10} {'Latency':<10} {'Details'}{RESET}"
    print(header)
    print("-" * 100)

    all_passed = True
    for r in results:
        status_str = format_status(r["passed"])
        if not r["passed"]:
            all_passed = False
        latency_str = f"{r['latency_ms']:.1f}ms" if r["latency_ms"] > 0 else "N/A"
        print(f"{r['name']:<28} {r['target']:<28} {status_str:<19} {latency_str:<10} {r['details']}")

    print("-" * 100)
    passed_count = sum(1 for r in results if r["passed"])
    total_count = len(results)

    if all_passed:
        print(f"{BOLD}{GREEN}OVERALL STATUS: PASS — ALL {total_count} CHECKS OPERATIONAL ({passed_count}/{total_count}){RESET}")
    else:
        failed_count = total_count - passed_count
        print(f"{BOLD}{RED}OVERALL STATUS: FAIL — {failed_count} OF {total_count} CHECKS FAILED ({passed_count}/{total_count} PASSED){RESET}")
    print(f"{BOLD}{CYAN}===================================================================================================={RESET}\n")
    return all_passed


def main():
    parser = argparse.ArgumentParser(description="PREVENT-X Security Lab Health Checker")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--no-pause", action="store_true", help="Non-interactive mode (for batch execution)")
    args = parser.parse_args()

    results = run_all_checks()

    if args.json:
        all_passed = all(r["passed"] for r in results)
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "all_passed": all_passed,
            "passed_count": sum(1 for r in results if r["passed"]),
            "total_count": len(results),
            "results": results,
        }
        print(json.dumps(payload, indent=2))
        sys.exit(0 if all_passed else 1)

    all_passed = print_table(results)
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
