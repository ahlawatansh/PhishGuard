import socket
import ssl
import time
import uuid
import json
import urllib.request
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse


class NetworkEngine:
    def __init__(self, max_events: int = 500):
        self.max_events = max_events
        self.events: List[Dict[str, Any]] = []
        self.firewall_rules: List[Dict[str, Any]] = []
        self.domain_age_cache: Dict[str, Dict[str, Any]] = {}
        self.request_stats = {
            "total_requests": 0,
            "predictions_count": 0,
            "dns_lookups_count": 0,
            "blocked_requests_count": 0,
            "error_count": 0,
            "total_response_time_ms": 0.0,
            "response_times_ms": []
        }

        self.add_firewall_rule(
            domain="malicious-phish-example.top",
            reason="Confirmed credential harvesting phishing host",
            action="BLOCK"
        )

    def log_event(self, event_type: str, severity: str, message: str, details: Optional[Dict[str, Any]] = None):
        event = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "severity": severity,
            "message": message,
            "details": details or {}
        }
        self.events.insert(0, event)
        if len(self.events) > self.max_events:
            self.events.pop()
        return event

    def record_request_metric(self, duration_ms: float, is_error: bool = False, is_prediction: bool = False, is_dns: bool = False):
        self.request_stats["total_requests"] += 1
        self.request_stats["total_response_time_ms"] += duration_ms
        if is_error:
            self.request_stats["error_count"] += 1
        if is_prediction:
            self.request_stats["predictions_count"] += 1
        if is_dns:
            self.request_stats["dns_lookups_count"] += 1

        self.request_stats["response_times_ms"].append(duration_ms)
        if len(self.request_stats["response_times_ms"]) > 1000:
            self.request_stats["response_times_ms"].pop(0)

    def get_network_stats(self) -> Dict[str, Any]:
        total = self.request_stats["total_requests"]
        times = self.request_stats["response_times_ms"]
        avg_latency = (self.request_stats["total_response_time_ms"] / total) if total > 0 else 0.0
        median_latency = float(sorted(times)[len(times) // 2]) if times else 0.0

        return {
            "total_requests": total,
            "predictions_count": self.request_stats["predictions_count"],
            "dns_lookups_count": self.request_stats["dns_lookups_count"],
            "blocked_requests_count": self.request_stats["blocked_requests_count"],
            "error_count": self.request_stats["error_count"],
            "avg_latency_ms": round(avg_latency, 2),
            "median_latency_ms": round(median_latency, 2),
            "active_firewall_rules": len(self.firewall_rules),
            "total_logged_events": len(self.events)
        }

    def resolve_dns(self, hostname: str, timeout: float = 3.0) -> Dict[str, Any]:
        clean_host = hostname.strip().lower()
        if "://" in clean_host:
            clean_host = urlparse(clean_host).netloc
        if "/" in clean_host:
            clean_host = clean_host.split("/")[0]
        if ":" in clean_host and not clean_host.count(":") > 1:
            clean_host = clean_host.split(":")[0]

        t0 = time.time()
        ipv4_addresses = []
        ipv6_addresses = []
        status = "SUCCESS"
        error_msg = None

        orig_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(timeout)

            try:
                addr_info = socket.getaddrinfo(clean_host, None, socket.AF_INET, socket.SOCK_STREAM)
                ipv4_addresses = sorted(list(set(item[4][0] for item in addr_info)))
            except socket.gaierror as e:
                error_msg = f"DNS resolution failed: {e.strerror}"
                status = "FAILED"
            except socket.timeout:
                error_msg = "DNS resolution timed out"
                status = "TIMEOUT"

            if status != "TIMEOUT":
                try:
                    addr_info_v6 = socket.getaddrinfo(clean_host, None, socket.AF_INET6, socket.SOCK_STREAM)
                    ipv6_addresses = sorted(list(set(item[4][0] for item in addr_info_v6)))
                except Exception:
                    pass

        finally:
            socket.setdefaulttimeout(orig_timeout)

        elapsed_ms = round((time.time() - t0) * 1000, 2)

        result = {
            "hostname": clean_host,
            "status": status,
            "ipv4_addresses": ipv4_addresses,
            "ipv6_addresses": ipv6_addresses,
            "lookup_duration_ms": elapsed_ms,
            "error": error_msg,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        sev = "INFO" if status == "SUCCESS" else "WARNING"
        msg = f"DNS resolution for '{clean_host}' returned {len(ipv4_addresses)} IPv4 addresses ({elapsed_ms} ms)" if status == "SUCCESS" else f"DNS resolution for '{clean_host}' failed: {error_msg}"
        self.log_event("DNS_LOOKUP", sev, msg, result)
        self.record_request_metric(elapsed_ms, is_error=(status != "SUCCESS"), is_dns=True)

        return result

    def inspect_target_telemetry(self, target_url: str, timeout: float = 2.5) -> Dict[str, Any]:
        parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
        scheme = parsed.scheme.lower() or "https"
        netloc = parsed.netloc or target_url
        hostname = netloc.split(":")[0].strip().lower()
        default_port = 443 if scheme == "https" else 80
        port = parsed.port or default_port

        dns_ms = 0.0
        tcp_ms = 0.0
        tls_info = None
        resolved_ips = []
        tcp_status = "UNKNOWN"
        error_msg = None

        t_dns = time.time()
        try:
            addr_info = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
            resolved_ips = sorted(list(set(x[4][0] for x in addr_info)))
            dns_ms = round((time.time() - t_dns) * 1000, 2)
        except Exception as e:
            dns_ms = round((time.time() - t_dns) * 1000, 2)
            error_msg = f"DNS lookup failed: {e}"
            return {
                "hostname": hostname,
                "scheme": scheme,
                "port": port,
                "dns_status": "FAILED",
                "dns_ms": dns_ms,
                "resolved_ips": [],
                "target_ip": None,
                "tcp_status": "UNREACHABLE",
                "tcp_handshake_ms": 0.0,
                "tls": None,
                "error": error_msg
            }

        target_ip = resolved_ips[0] if resolved_ips else None

        t_tcp = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        tcp_connected = False
        try:
            sock.connect((target_ip, port))
            tcp_ms = round((time.time() - t_tcp) * 1000, 2)
            tcp_status = "OPEN"
            tcp_connected = True
        except socket.timeout:
            tcp_ms = round((time.time() - t_tcp) * 1000, 2)
            tcp_status = "TIMEOUT"
            error_msg = "TCP SYN handshake timed out"
        except ConnectionRefusedError:
            tcp_ms = round((time.time() - t_tcp) * 1000, 2)
            tcp_status = "REFUSED"
            error_msg = "Connection refused (RST packet returned)"
        except Exception as e:
            tcp_ms = round((time.time() - t_tcp) * 1000, 2)
            tcp_status = "FAILED"
            error_msg = str(e)

        if port == 443 and tcp_connected:
            t_tls = time.time()
            ctx = ssl.create_default_context()
            try:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_ms = round((time.time() - t_tls) * 1000, 2)
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))

                    tls_info = {
                        "version": ssock.version() or "TLSv1.3",
                        "cipher_suite": cipher[0] if cipher else "Unknown",
                        "tls_handshake_ms": tls_ms,
                        "issuer_org": issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Trusted CA",
                        "valid_to": cert.get("notAfter", "Active"),
                        "status": "VALID"
                    }
            except ssl.SSLCertVerificationError as e:
                tls_info = {
                    "version": "TLS",
                    "cipher_suite": "UNVERIFIED",
                    "tls_handshake_ms": round((time.time() - t_tls) * 1000, 2),
                    "issuer_org": "Self-Signed / Untrusted CA",
                    "valid_to": "Expired / Invalid",
                    "status": "INVALID_CERT",
                    "error": str(e)
                }
            except Exception as e:
                tls_info = {
                    "version": "TLS",
                    "cipher_suite": "ERROR",
                    "tls_handshake_ms": round((time.time() - t_tls) * 1000, 2),
                    "issuer_org": "Unknown",
                    "valid_to": "Unknown",
                    "status": "HANDSHAKE_FAILED",
                    "error": str(e)
                }
        else:
            try:
                sock.close()
            except Exception:
                pass

        telemetry = {
            "hostname": hostname,
            "scheme": scheme.upper(),
            "port": port,
            "dns_status": "RESOLVED",
            "dns_ms": dns_ms,
            "resolved_ips": resolved_ips,
            "target_ip": target_ip,
            "tcp_status": tcp_status,
            "tcp_handshake_ms": tcp_ms,
            "tls": tls_info,
            "error": error_msg
        }

        self.record_request_metric(tcp_ms + dns_ms, is_error=(tcp_status != "OPEN"))
        self.log_event(
            "NETWORK_TELEMETRY",
            "INFO" if tcp_status == "OPEN" else "WARNING",
            f"Network Telemetry for '{hostname}': DNS {dns_ms}ms, TCP {tcp_status} ({tcp_ms}ms)" + (f", TLS {tls_info['version']}" if tls_info else ""),
            telemetry
        )

        return telemetry

    def ping_target_socket(self, hostname: str, port: int = 443, count: int = 3) -> Dict[str, Any]:
        clean_host = hostname.strip().lower()
        if "://" in clean_host:
            clean_host = urlparse(clean_host).netloc
        clean_host = clean_host.split("/")[0].split(":")[0]

        rtts = []
        for _ in range(count):
            t_probe = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            try:
                s.connect((clean_host, port))
                rtt = round((time.time() - t_probe) * 1000, 2)
                rtts.append(rtt)
            except Exception:
                pass
            finally:
                s.close()
            time.sleep(0.05)

        avg_rtt = round(sum(rtts) / len(rtts), 2) if rtts else 0.0
        min_rtt = min(rtts) if rtts else 0.0
        max_rtt = max(rtts) if rtts else 0.0
        jitter = round(max_rtt - min_rtt, 2) if rtts else 0.0

        return {
            "hostname": clean_host,
            "port": port,
            "probes_sent": count,
            "probes_received": len(rtts),
            "rtt_samples_ms": rtts,
            "avg_rtt_ms": avg_rtt,
            "min_rtt_ms": min_rtt,
            "max_rtt_ms": max_rtt,
            "jitter_ms": jitter,
            "packet_loss_pct": round(((count - len(rtts)) / count) * 100, 1)
        }

    def is_domain_blocked(self, domain_or_url: str) -> Optional[Dict[str, Any]]:
        raw = domain_or_url.strip().lower()
        if "://" in raw:
            raw = urlparse(raw).netloc
        if "/" in raw:
            raw = raw.split("/")[0]
        raw = raw.split(":")[0]

        for rule in self.firewall_rules:
            target = rule["domain"].lower()
            if raw == target or raw.endswith("." + target):
                self.request_stats["blocked_requests_count"] += 1
                self.log_event(
                    "BLOCKED_TRAFFIC",
                    "CRITICAL",
                    f"Simulated Firewall intercepted request to blocked domain: '{raw}' (Rule: {rule['id']})",
                    {"matched_rule": rule, "intercepted_domain": raw}
                )
                return rule
        return None

    def add_firewall_rule(self, domain: str, reason: str, action: str = "BLOCK") -> Dict[str, Any]:
        clean_domain = domain.strip().lower()
        if "://" in clean_domain:
            clean_domain = urlparse(clean_domain).netloc
        clean_domain = clean_domain.split("/")[0].split(":")[0]

        if not clean_domain:
            raise ValueError("Domain cannot be empty")

        for r in self.firewall_rules:
            if r["domain"] == clean_domain:
                return r

        rule = {
            "id": f"FW-{str(uuid.uuid4())[:6].upper()}",
            "domain": clean_domain,
            "reason": reason.strip() or "Suspected phishing infrastructure",
            "action": action.upper(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "hits_count": 0,
            "enforced": True
        }
        self.firewall_rules.insert(0, rule)
        self.log_event(
            "FIREWALL_ACTION",
            "WARNING",
            f"Simulated firewall rule created: BLOCK {clean_domain} ({rule['id']})",
            rule
        )
        return rule

    def remove_firewall_rule(self, rule_id: str) -> bool:
        for i, rule in enumerate(self.firewall_rules):
            if rule["id"] == rule_id:
                removed = self.firewall_rules.pop(i)
                self.log_event(
                    "FIREWALL_ACTION",
                    "INFO",
                    f"Simulated firewall rule removed: {removed['domain']} ({rule_id})",
                    removed
                )
                return True
        return False

    def get_domain_age(self, hostname: str) -> Dict[str, Any]:
        clean_host = hostname.strip().lower()
        if "://" in clean_host:
            clean_host = urlparse(clean_host).netloc
        clean_host = clean_host.split("/")[0].split(":")[0]

        parts = clean_host.split('.')
        compound_tlds = {
            'ac.in', 'co.in', 'gov.in', 'edu.in', 'org.in', 'net.in',
            'co.uk', 'ac.uk', 'org.uk', 'gov.uk', 'co.jp', 'com.au', 'co.nz', 'co.za'
        }
        if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in compound_tlds:
            root_domain = f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        elif len(parts) >= 2:
            root_domain = f"{parts[-2]}.{parts[-1]}"
        else:
            root_domain = clean_host

        if root_domain in self.domain_age_cache:
            return self.domain_age_cache[root_domain]

        try:
            req = urllib.request.Request(
                f"https://rdap.org/domain/{root_domain}",
                headers={"User-Agent": "Mozilla/5.0 (SecurityScanner/1.0)"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode())
                for ev in data.get("events", []):
                    if ev.get("eventAction") == "registration":
                        reg_dt = datetime.fromisoformat(ev.get("eventDate").replace("Z", "+00:00"))
                        now = datetime.now(timezone.utc)
                        days = (now - reg_dt).days
                        years = days // 365
                        if years >= 1:
                            age_str = f"{years} years ago"
                        else:
                            age_str = f"{days} days ago"
                        res = {
                            "root_domain": root_domain,
                            "age_years": years,
                            "age_days": days,
                            "age_str": age_str,
                            "registration_date": ev.get("eventDate")
                        }
                        self.domain_age_cache[root_domain] = res
                        return res
        except Exception:
            pass

        res = {
            "root_domain": root_domain,
            "age_years": None,
            "age_days": None,
            "age_str": None,
            "registration_date": None
        }
        self.domain_age_cache[root_domain] = res
        return res

    def generate_safety_report(self, url: str, prediction: Dict[str, Any], telemetry: Dict[str, Any], is_blocked: bool) -> Dict[str, Any]:
        clean_url = url.strip()
        parsed = urlparse(clean_url if "://" in clean_url else f"https://{clean_url}")
        hostname = parsed.netloc.split(":")[0].lower() or clean_url

        is_phish = prediction.get("is_phishing", False)
        age_data = self.get_domain_age(hostname)
        age_str = age_data.get("age_str")

        tls = telemetry.get("tls")
        tls_valid = bool(tls and tls.get("status") == "VALID")

        observations = []
        if is_phish or is_blocked:
            icon = "🚨"
            headline = "Suspicious — High Risk"
            summary = f"{hostname} was flagged as risky based on the security checks we completed."

            indicators = prediction.get("indicators", [])
            if is_blocked:
                observations.append("Domain is actively blocked in our security firewall rules.")
            if indicators:
                for ind in indicators:
                    observations.append(ind)
            else:
                observations.append("Structural and statistical anomaly detected in URL.")

            if not tls_valid:
                observations.append("The website does not present a verified security certificate.")
            if age_str:
                observations.append(f"Domain registered {age_str}.")

            recommendation = "Do not enter passwords or financial details on this site. Leave immediately if anything feels unusual."
        else:
            icon = "✅"
            headline = "Looks safe"
            summary = f"{hostname} looks safe based on the checks we completed."

            observations.append("No malicious patterns or threats detected in the site's structure.")
            if tls_valid:
                observations.append("The website uses a valid security certificate.")
            else:
                observations.append("The domain structure and DNS records resolve normally.")

            observations.append("No reports were found in Scam Archive.")
            if age_str:
                observations.append(f"The website was registered {age_str}.")
            else:
                observations.append("Domain registration verified with authoritative registries.")

            recommendation = "You can use the site, but leave if anything feels unusual—trust your instincts."

        return {
            "icon": icon,
            "headline": headline,
            "summary": summary,
            "observations": observations,
            "recommendation": recommendation,
            "domain_age": age_str,
            "root_domain": age_data.get("root_domain", hostname)
        }


_network_engine_instance = None


def get_network_engine() -> NetworkEngine:
    global _network_engine_instance
    if _network_engine_instance is None:
        _network_engine_instance = NetworkEngine()
    return _network_engine_instance
