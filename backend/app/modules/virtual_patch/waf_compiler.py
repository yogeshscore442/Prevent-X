"""
PREVENT-X WAF Configuration Compiler (MOD-06, MOD-08)
Compiles structured virtual patch rules into valid, syntax-checked Nginx reverse proxy configurations.
"""

import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from backend.app.models.virtual_patch import AttackType, PatchAction, VirtualPatchRule

logger = logging.getLogger("preventx.virtual_patch.compiler")


class WafConfigCompiler:
    """
    Compiles structured virtual patch rules into validated Nginx reverse proxy directives.
    """

    @classmethod
    def validate_rule_syntax(cls, rule: VirtualPatchRule) -> Tuple[bool, Optional[str]]:
        """
        Validates regex patterns and syntax in match conditions.
        Returns (is_valid, error_message).
        """
        try:
            conditions = json.loads(rule.match_conditions or "[]") if isinstance(rule.match_conditions, str) else rule.match_conditions or []
            for cond in conditions:
                pattern = cond.get("pattern", "")
                if cond.get("operator") == "REGEX":
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        return False, f"Invalid regular expression '{pattern}': {e}"
            return True, None
        except Exception as e:
            return False, f"Syntax parsing failure: {e}"

    @classmethod
    def compile_rule_to_nginx_directives(cls, rule: VirtualPatchRule) -> List[str]:
        """
        Translates a single VirtualPatchRule into Nginx location/if directives.
        """
        directives: List[str] = []
        is_valid, err = cls.validate_rule_syntax(rule)
        if not is_valid:
            logger.warning("Skipping invalid rule %s (%s): %s", rule.id, rule.rule_name, err)
            return []

        if not rule.is_active:
            return []

        rule_id_str = str(rule.id)
        attack_type = rule.attack_type
        action_code = 403 if rule.action == PatchAction.BLOCK.value else 200

        # Method restriction rule
        if rule.attack_type == AttackType.METHOD_RESTRICTION.value:
            methods = json.loads(rule.http_methods or "[]")
            if methods:
                method_regex = "^(" + "|".join(methods) + ")$"
                directives.append(f"        # Rule: {rule.rule_name} (Priority {rule.priority})")
                directives.append(f'        if ($request_method ~* "{method_regex}") {{')
                directives.append(f'            add_header Content-Type application/json always;')
                directives.append(f'            add_header X-WAF-Blocked "1" always;')
                directives.append(f'            add_header X-WAF-Rule-ID "{rule_id_str}" always;')
                directives.append(f'            add_header X-WAF-Attack-Type "{attack_type}" always;')
                directives.append(f'            return 405 \'{{"error": "Method Not Allowed", "waf_blocked": true, "rule_id": "{rule_id_str}"}}\';')
                directives.append("        }")
                return directives

        # Match condition checks
        conditions = json.loads(rule.match_conditions or "[]")
        for cond in conditions:
            target = cond.get("target", "QUERY").upper()
            pattern = cond.get("pattern", "")
            # Escape double quotes for Nginx configuration
            escaped_pattern = pattern.replace('"', '\\"')

            directives.append(f"        # Rule: {rule.rule_name} (Target: {target}, Priority: {rule.priority})")

            if target == "URI":
                nginx_var = "$request_uri"
            elif target == "QUERY":
                nginx_var = "$args"
            elif target == "HEADER":
                h_name = cond.get("header_name", "user-agent").lower().replace("-", "_")
                nginx_var = f"$http_{h_name}"
            else:
                nginx_var = "$args"

            # Case-insensitive Nginx match operator (~*)
            directives.append(f'        if ({nginx_var} ~* "{escaped_pattern}") {{')
            directives.append(f'            add_header Content-Type application/json always;')
            directives.append(f'            add_header X-WAF-Blocked "1" always;')
            directives.append(f'            add_header X-WAF-Rule-ID "{rule_id_str}" always;')
            directives.append(f'            add_header X-WAF-Attack-Type "{attack_type}" always;')
            directives.append(
                f'            return {action_code} \'{{"error": "Forbidden", "waf_blocked": true, '
                f'"rule_id": "{rule_id_str}", "attack_type": "{attack_type}", '
                f'"incident_timestamp": "$time_iso8601"}}\';'
            )
            directives.append("        }")

        return directives

    @classmethod
    def generate_full_nginx_config(
        cls,
        rules: List[VirtualPatchRule],
        listen_port: int,
        upstream_url: str,
        organization_name: str = "SMB Tenant",
    ) -> Tuple[str, str]:
        """
        Generates complete standalone nginx.conf with all active rules and OWASP security headers.
        Returns (full_config_content, config_hash).
        """
        # Sort rules by priority ascending (lower priority number executes first)
        sorted_rules = sorted(rules, key=lambda r: r.priority)

        waf_directives = []
        for r in sorted_rules:
            snippet = cls.compile_rule_to_nginx_directives(r)
            if snippet:
                waf_directives.extend(snippet)

        waf_block = "\n".join(waf_directives)

        # Parse upstream host:port
        clean_upstream = upstream_url.replace("http://", "").replace("https://", "").rstrip("/")
        if ":" not in clean_upstream:
            clean_upstream += ":80"

        config_template = f"""# PREVENT-X Virtual Patching Engine - Reverse Proxy Configuration
# Tenant: {organization_name}
# Listen Port: {listen_port} | Upstream: {upstream_url}

worker_processes 1;
error_log logs/error.log warn;
pid logs/nginx.pid;

events {{
    worker_connections 1024;
}}

http {{
    include mime.types;
    default_type application/octet-stream;
    server_tokens off;
    sendfile on;
    keepalive_timeout 65;

    # Upstream application cluster
    upstream backend_upstream {{
        server {clean_upstream};
        keepalive 16;
    }}

    server {{
        listen {listen_port};
        server_name localhost;

        # OWASP Security Headers
        add_header X-Frame-Options "DENY" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-WAF-Engine "PREVENT-X-Intelligent-WAF" always;

        # Reverse Proxy to Upstream Application with Inline Virtual Patch Rules
        location / {{
            # Intelligent Virtual Patch Rules
{waf_block}

            proxy_pass http://backend_upstream;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 10s;
            proxy_read_timeout 30s;
        }}
    }}
}}
"""
        config_hash = hashlib.sha256(config_template.encode("utf-8")).hexdigest()
        return config_template, config_hash
