import re
import math
from collections import Counter
from typing import Dict, Any, List

SUSPICIOUS_TLDS = {'xyz', 'win', 'top', 'tk', 'pw', 'info', 'ml'}

FEATURE_NAMES: List[str] = [
    'url_length', 'domain_length', 'hostname_length', 'path_length', 'first_dir_length',
    'tld_length', 'tld_length_domain', 'url_depth', 'query_length', 'path_segments_count',
    'num_digits', 'num_letters', 'num_special_chars', 'num_dots', 'num_hyphens',
    'num_at', 'num_percent', 'num_equals', 'num_question', 'num_ampersand',
    'num_hash', 'num_underscore', 'num_special', 'num_slash', 'num_params',
    'entropy_url', 'entropy_hostname', 'entropy_domain', 'entropy_path', 'query_entropy',
    'ratio_digits', 'ratio_letters', 'ratio_special_chars', 'uppercase_ratio', 'lowercase_ratio',
    'is_ip_address', 'starts_with_ip', 'is_suspicious_tld', 'uses_https', 'has_www',
    'unusual_double_slash', 'multiple_http', 'contains_port_number', 'path_has_encoded_chars',
    'query_has_base64', 'contains_login', 'contains_secure', 'contains_verify',
    'contains_account', 'contains_update', 'contains_bank', 'contains_cloud', 'contains_brand',
    'query_key_count', 'query_value_length_avg'
]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    cnt = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in cnt.values())


def extract_features(url: str) -> Dict[str, Any]:
    url_str = str(url).strip()
    url_len = len(url_str)

    uses_https = 1 if url_str.startswith('https://') else 0

    s = url_str
    for pfx in ['http://', 'https://', 'ftp://']:
        if s.startswith(pfx):
            s = s[len(pfx):]
            break

    if '/' in s:
        netloc, rest = s.split('/', 1)
        path_str = '/' + rest
    else:
        netloc = s
        path_str = ''

    if '?' in path_str:
        path_part, query_part = path_str.split('?', 1)
        if '#' in query_part:
            query_part = query_part.split('#')[0]
    else:
        path_part = path_str.split('#')[0]
        query_part = ''

    path_len = len(path_part)
    query_len = len(query_part)

    hostname = netloc.split('?')[0].split('#')[0]
    hostname_len = len(hostname)

    clean_host = hostname.split('@')[-1] if '@' in hostname else hostname
    clean_host_no_port = clean_host.split(':')[0]

    host_parts = clean_host_no_port.split('.')
    if len(host_parts) >= 2:
        tld_part = host_parts[-1]
        if tld_part.isalpha():
            tld_len = len(tld_part)
            domain_part = host_parts[-2]
            domain_len = len(domain_part)
        else:
            tld_len = 0
            domain_part = tld_part
            domain_len = len(domain_part)
    elif len(host_parts) == 1:
        domain_part = host_parts[0]
        domain_len = len(domain_part)
        tld_len = 0
    else:
        domain_part = ''
        domain_len = 0
        tld_len = 0

    tld_length = tld_len
    tld_length_domain = tld_len

    raw_segments = [p for p in path_part.split('/') if p]
    url_depth = len(raw_segments)
    path_segments_count = url_depth
    first_dir_length = len(raw_segments[0]) if raw_segments else 0

    num_digits = sum(1 for c in url_str if c.isdigit())
    num_letters = sum(1 for c in url_str if c.isalpha())
    num_special_chars = sum(1 for c in url_str if not c.isalnum())
    num_special = num_special_chars

    num_dots = url_str.count('.')
    num_hyphens = url_str.count('-')
    num_at = url_str.count('@')
    num_percent = url_str.count('%')
    num_equals = url_str.count('=')
    num_question = url_str.count('?')
    num_ampersand = url_str.count('&')
    num_hash = url_str.count('#')
    num_underscore = url_str.count('_')
    num_slash = url_str.count('/')

    if query_part:
        q_params = [p for p in query_part.split('&') if p]
        num_params = len(q_params)
        query_key_count = num_params
        val_lens = [len(qp.split('=', 1)[1]) if '=' in qp else 0 for qp in q_params]
        query_val_avg = float(sum(val_lens) / len(val_lens)) if val_lens else 0.0
    else:
        num_params = 0
        query_key_count = 0
        query_val_avg = 0.0

    entropy_url = shannon_entropy(url_str)
    entropy_hostname = shannon_entropy(hostname)
    entropy_domain = shannon_entropy(domain_part)
    entropy_path = shannon_entropy(path_part)
    query_entropy = shannon_entropy(query_part)

    ratio_digits = (num_digits / url_len) if url_len > 0 else 0.0
    ratio_letters = (num_letters / url_len) if url_len > 0 else 0.0
    ratio_special_chars = (num_special_chars / url_len) if url_len > 0 else 0.0
    uppercase_ratio = (sum(1 for c in url_str if c.isupper()) / url_len) if url_len > 0 else 0.0
    lowercase_ratio = (sum(1 for c in url_str if c.islower()) / url_len) if url_len > 0 else 0.0

    is_ip = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', clean_host_no_port) else 0
    starts_with_ip = is_ip

    is_suspicious_tld = 1 if (host_parts[-1].lower() in SUSPICIOUS_TLDS) else 0
    has_www = 1 if 'www.' in clean_host.lower() else 0
    unusual_double_slash = 1 if '//' in url_str.split('://', 1)[-1] else 0

    lower_url = url_str.lower()
    multiple_http = 1 if (lower_url.count('http:') + lower_url.count('https:') > 1) else 0

    port_match = re.search(r':\d{2,5}', clean_host)
    contains_port_number = 1 if port_match else 0

    path_has_encoded_chars = 1 if ('%' in path_part) else 0
    query_has_base64 = 1 if (re.search(r'[A-Za-z0-9+/]{20,}={0,2}', query_part)) else 0

    contains_login = 1 if 'login' in lower_url else 0
    contains_secure = 1 if 'secure' in lower_url else 0
    contains_verify = 1 if 'verify' in lower_url else 0
    contains_account = 1 if 'account' in lower_url else 0
    contains_update = 1 if 'update' in lower_url else 0
    contains_bank = 1 if 'bank' in lower_url else 0
    contains_cloud = 1 if 'cloud' in lower_url else 0
    contains_brand = 1 if 'brand' in lower_url else 0

    return {
        'url_length': url_len,
        'domain_length': domain_len,
        'hostname_length': hostname_len,
        'path_length': path_len,
        'first_dir_length': first_dir_length,
        'tld_length': tld_length,
        'tld_length_domain': tld_length_domain,
        'url_depth': url_depth,
        'query_length': query_len,
        'path_segments_count': path_segments_count,
        'num_digits': num_digits,
        'num_letters': num_letters,
        'num_special_chars': num_special_chars,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_at': num_at,
        'num_percent': num_percent,
        'num_equals': num_equals,
        'num_question': num_question,
        'num_ampersand': num_ampersand,
        'num_hash': num_hash,
        'num_underscore': num_underscore,
        'num_special': num_special,
        'num_slash': num_slash,
        'num_params': num_params,
        'entropy_url': entropy_url,
        'entropy_hostname': entropy_hostname,
        'entropy_domain': entropy_domain,
        'entropy_path': entropy_path,
        'query_entropy': query_entropy,
        'ratio_digits': ratio_digits,
        'ratio_letters': ratio_letters,
        'ratio_special_chars': ratio_special_chars,
        'uppercase_ratio': uppercase_ratio,
        'lowercase_ratio': lowercase_ratio,
        'is_ip_address': is_ip,
        'starts_with_ip': starts_with_ip,
        'is_suspicious_tld': is_suspicious_tld,
        'uses_https': uses_https,
        'has_www': has_www,
        'unusual_double_slash': unusual_double_slash,
        'multiple_http': multiple_http,
        'contains_port_number': contains_port_number,
        'path_has_encoded_chars': path_has_encoded_chars,
        'query_has_base64': query_has_base64,
        'contains_login': contains_login,
        'contains_secure': contains_secure,
        'contains_verify': contains_verify,
        'contains_account': contains_account,
        'contains_update': contains_update,
        'contains_bank': contains_bank,
        'contains_cloud': contains_cloud,
        'contains_brand': contains_brand,
        'query_key_count': query_key_count,
        'query_value_length_avg': query_val_avg
    }


def extract_features_vector(url: str) -> List[float]:
    feats = extract_features(url)
    return [float(feats[fn]) for fn in FEATURE_NAMES]
