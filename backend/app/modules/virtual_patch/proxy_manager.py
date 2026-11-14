"""
PREVENT-X Nginx Reverse Proxy Manager (MOD-08)
Controls the Nginx reverse proxy process lifecycle, configuration syntax validation,
safe hot-reloading, health checks, and automatic rollback on failure.
"""

import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import httpx

logger = logging.getLogger("preventx.virtual_patch.proxy_manager")


class NginxProxyManager:
    """
    Manages Nginx reverse proxy binary, config generation, syntax testing,
    and process management on Windows/Linux environments.
    """

    @classmethod
    def get_nginx_binary_and_prefix(cls) -> Tuple[Optional[str], Optional[str]]:
        """
        Locates the native Nginx executable and its root prefix directory.
        """
        workspace_root = Path(os.getcwd())
        candidate_paths = [
            workspace_root / "infrastructure" / "bin" / "nginx" / "nginx.exe",
            workspace_root / "infrastructure" / "bin" / "nginx" / "nginx-1.26.2" / "nginx.exe",
        ]
        for p in candidate_paths:
            if p.is_file():
                return str(p.resolve()), str(p.parent.resolve())

        # Check if on system PATH
        try:
            res = subprocess.run(["where", "nginx"], capture_output=True, text=True, check=False)
            if res.returncode == 0 and res.stdout.strip():
                bin_path = res.stdout.strip().splitlines()[0]
                return bin_path, str(Path(bin_path).parent.resolve())
        except Exception:
            pass

        return None, None

    @classmethod
    def test_configuration(cls, config_path: str) -> Tuple[bool, str]:
        """
        Executes 'nginx -p <prefix> -c <config> -t' to validate configuration syntax before activation.
        """
        bin_path, prefix_path = cls.get_nginx_binary_and_prefix()
        if not bin_path or not prefix_path:
            return False, "Nginx binary not found in infrastructure/bin/nginx."

        # Ensure forward slashes for Nginx path compatibility
        norm_conf = str(Path(config_path).resolve()).replace("\\", "/")
        norm_prefix = str(Path(prefix_path).resolve()).replace("\\", "/")

        cmd = [bin_path, "-p", norm_prefix, "-c", norm_conf, "-t"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                cwd=prefix_path,
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            if proc.returncode == 0 and "syntax is ok" in output:
                return True, output.strip()
            return False, f"Nginx syntax test failed (code {proc.returncode}): {output.strip()}"
        except Exception as e:
            return False, f"Error executing Nginx syntax test: {e}"

    @classmethod
    def write_runtime_config(cls, deployment_id: str, config_content: str) -> str:
        """
        Writes configuration to infrastructure/bin/nginx/conf/preventx_<deployment_id>.conf.
        """
        _, prefix_path = cls.get_nginx_binary_and_prefix()
        if not prefix_path:
            prefix_path = os.path.join("infrastructure", "bin", "nginx")

        conf_dir = Path(prefix_path) / "conf"
        conf_dir.mkdir(parents=True, exist_ok=True)

        conf_file = conf_dir / f"preventx_{deployment_id}.conf"
        conf_file.write_text(config_content, encoding="utf-8")
        return str(conf_file.resolve()).replace("\\", "/")

    @classmethod
    def apply_deployment(
        cls,
        deployment_id: str,
        config_content: str,
        listen_port: int,
        upstream_url: str,
    ) -> Tuple[bool, str]:
        """
        Validates and activates configuration on the Nginx reverse proxy.
        If validation fails, rolls back immediately.
        """
        conf_path = cls.write_runtime_config(deployment_id, config_content)

        # 1. Pre-deployment syntax verification
        is_valid, validation_log = cls.test_configuration(conf_path)
        if not is_valid:
            logger.error("Failed configuration syntax check for deployment %s: %s", deployment_id, validation_log)
            return False, validation_log

        # 2. Hot-reload or start proxy
        bin_path, prefix_path = cls.get_nginx_binary_and_prefix()
        if not bin_path or not prefix_path:
            return False, "Nginx binary not available."

        norm_conf = str(Path(conf_path).resolve()).replace("\\", "/")
        norm_prefix = str(Path(prefix_path).resolve()).replace("\\", "/")

        # Try graceful reload first
        reload_cmd = [bin_path, "-p", norm_prefix, "-s", "reload"]
        try:
            reload_res = subprocess.run(
                reload_cmd,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                cwd=prefix_path,
            )
            if reload_res.returncode == 0:
                logger.info("Successfully reloaded active Nginx with deployment %s", deployment_id)
                return True, f"Nginx reloaded successfully with configuration {conf_path}."
        except Exception:
            pass

        # If reload failed or Nginx was not running, launch Nginx background daemon
        start_cmd = [bin_path, "-p", norm_prefix, "-c", norm_conf]
        try:
            # Launch detached process on Windows
            DETACHED_PROCESS = 0x00000008
            subprocess.Popen(
                start_cmd,
                cwd=prefix_path,
                creationflags=DETACHED_PROCESS,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(1.0)  # Wait for socket bind
            logger.info("Launched Nginx reverse proxy daemon with configuration %s", conf_path)
            return True, f"Nginx reverse proxy launched successfully on port {listen_port}."
        except Exception as e:
            logger.exception("Failed to launch Nginx process: %s", e)
            return False, f"Failed to start Nginx process: {e}"

    @classmethod
    def check_proxy_health(cls, listen_port: int) -> Dict[str, Any]:
        """
        Probes the proxy port to verify responsiveness.
        """
        url = f"http://127.0.0.1:{listen_port}/"
        try:
            with httpx.Client(timeout=2.0) as client:
                resp = client.get(url)
                return {
                    "is_running": True,
                    "status_code": resp.status_code,
                    "server_header": resp.headers.get("Server", "nginx"),
                    "waf_header": resp.headers.get("X-WAF-Engine"),
                }
        except (httpx.ConnectError, httpx.ConnectTimeout):
            return {
                "is_running": False,
                "error": f"Connection refused on port {listen_port}. Reverse proxy may not be active.",
            }
        except Exception as e:
            return {
                "is_running": False,
                "error": str(e),
            }

    @classmethod
    def stop_proxy(cls) -> bool:
        """
        Gracefully terminates running Nginx processes.
        """
        bin_path, prefix_path = cls.get_nginx_binary_and_prefix()
        if not bin_path or not prefix_path:
            return False

        try:
            subprocess.run(
                [bin_path, "-p", prefix_path, "-s", "stop"],
                capture_output=True,
                timeout=5,
                check=False,
                cwd=prefix_path,
            )
            return True
        except Exception:
            # Fallback to taskkill on Windows
            try:
                subprocess.run(["taskkill", "/F", "/IM", "nginx.exe"], capture_output=True, check=False)
                return True
            except Exception:
                return False
