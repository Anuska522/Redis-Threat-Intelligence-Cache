import re
import ipaddress
import hashlib
from urllib.parse import urlparse, urlunparse
from typing import Tuple
from app.models.indicator import IndicatorType, NormalizationResult


DOMAIN_REGEX = re.compile(
    r"^(?!-)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


class NormalizerService:
    @staticmethod
    def normalize(raw_indicator: str) -> NormalizationResult:
        if not raw_indicator or not isinstance(raw_indicator, str):
            raise ValueError("Indicator cannot be empty or non-string.")

        cleaned = raw_indicator.strip()
        if not cleaned:
            raise ValueError("Indicator cannot be whitespace only.")

        # Disallow control characters to prevent header/key injection
        if any(ord(c) < 32 or ord(c) == 127 for c in cleaned):
            raise ValueError("Indicator contains invalid control characters.")

        # Disallow spaces
        if " " in cleaned:
            raise ValueError("Indicator cannot contain whitespace.")

        # Disallow consecutive dots
        if ".." in cleaned:
            raise ValueError("Indicator contains invalid consecutive dots.")

        # Disallow unsupported URI schemes (e.g. ftp://, file://, ssh://)
        if "://" in cleaned:
            scheme = cleaned.split("://", 1)[0].lower()
            if scheme not in ("http", "https"):
                raise ValueError(f"Unsupported URI scheme: '{scheme}'. Only HTTP and HTTPS are permitted.")

        # 1. Attempt IP Address validation (IPv4 or IPv6)
        try:
            candidate_ip = cleaned
            if candidate_ip.startswith("[") and candidate_ip.endswith("]"):
                candidate_ip = candidate_ip[1:-1]

            ip_obj = ipaddress.ip_address(candidate_ip)
            normalized_ip = ip_obj.compressed.lower()
            redis_key = f"ti:ip:{normalized_ip}"

            return NormalizationResult(
                original=cleaned,
                normalized=normalized_ip,
                indicator_type=IndicatorType.IP,
                redis_key=redis_key,
                ip_version=ip_obj.version,
                lookup_hash=None
            )
        except ValueError:
            pass  # Not an IP address, continue

        # 2. Check if indicator is a URL (starts with http:// or https://, or has path/query with domain)
        is_explicit_url = cleaned.lower().startswith(("http://", "https://"))
        has_path_or_query = ("/" in cleaned and not cleaned.endswith("/")) or "?" in cleaned or "#" in cleaned

        if is_explicit_url or has_path_or_query:
            url_to_parse = cleaned if is_explicit_url else f"http://{cleaned}"
            try:
                parsed = urlparse(url_to_parse)
                if parsed.hostname:
                    hostname = parsed.hostname.lower()
                    try:
                        hostname = hostname.encode("idna").decode("ascii")
                    except Exception:
                        pass

                    # Normalize port
                    port = parsed.port
                    netloc = hostname
                    scheme = parsed.scheme.lower() if parsed.scheme else "http"
                    if scheme not in ("http", "https"):
                        raise ValueError(f"Unsupported URL scheme: {scheme}. Only HTTP and HTTPS are permitted.")

                    if port:
                        if not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
                            netloc = f"{hostname}:{port}"

                    path = parsed.path if parsed.path else "/"

                    canonical_url = urlunparse((
                        scheme,
                        netloc,
                        path,
                        parsed.params,
                        parsed.query,
                        ""
                    ))

                    url_hash = hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()
                    redis_key = f"ti:url:{url_hash}"

                    return NormalizationResult(
                        original=cleaned,
                        normalized=canonical_url,
                        indicator_type=IndicatorType.URL,
                        redis_key=redis_key,
                        lookup_hash=url_hash,
                        canonical_url=canonical_url,
                        port=port
                    )
            except ValueError:
                raise
            except Exception as e:
                if is_explicit_url:
                    raise ValueError(f"Malformed URL: {e}")

        # 3. Domain validation
        candidate_domain = cleaned.rstrip(".").lower()

        try:
            encoded_domain = candidate_domain.encode("idna").decode("ascii")
        except Exception:
            encoded_domain = candidate_domain

        if DOMAIN_REGEX.match(encoded_domain):
            redis_key = f"ti:domain:{encoded_domain}"
            return NormalizationResult(
                original=cleaned,
                normalized=encoded_domain,
                indicator_type=IndicatorType.DOMAIN,
                redis_key=redis_key,
                lookup_hash=None
            )

        raise ValueError(
            f"Invalid indicator: '{cleaned}' is not a valid IPv4, IPv6, domain name, or HTTP/HTTPS URL."
        )


normalizer = NormalizerService()
