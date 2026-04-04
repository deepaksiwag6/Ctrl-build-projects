import urllib.parse
import math
from collections import Counter
import re

def calculate_entropy(s):
    if not s:
        return 0
    p, lns = Counter(s), float(len(s))
    return -sum((count/lns) * math.log2(count/lns) for count in p.values())

def extract_kaggle_features(url: str):
    """
    Extracts purely URL-based features from a given URL to match 
    the Kaggle 'Phishing_Legitimate_full' dataset.
    """
    url_lower = url.lower()
    
    # Basic URL parsing
    if not url_lower.startswith('http'):
        url_lower = 'http://' + url_lower
        
    parsed = urllib.parse.urlparse(url_lower)
    domain_part = parsed.netloc.split(':')[0]
    path_part = parsed.path
    query_part = parsed.query
    
    # 1. NumDots
    num_dots = url_lower.count('.')
    
    # 2. SubdomainLevel
    # Basic estimation: dots in domain - 1 (for something like code.google.com -> 1, google.com -> 0)
    subdomain_level = max(0, domain_part.count('.') - 1)
    
    # 3. PathLevel
    path_level = max(0, path_part.count('/') - (1 if path_part.endswith('/') else 0))
    
    # 4. UrlLength
    url_length = len(url_lower)
    
    # 5. NumDash
    num_dash = url_lower.count('-')
    
    # 6. NumDashInHostname
    num_dash_in_hostname = domain_part.count('-')
    
    # 7. AtSymbol
    at_symbol = 1 if '@' in url_lower else 0
    
    # 8. TildeSymbol
    tilde_symbol = 1 if '~' in url_lower else 0
    
    # 9. NumUnderscore
    num_underscore = url_lower.count('_')
    
    # 10. NumPercent
    num_percent = url_lower.count('%')
    
    # 11. NumQueryComponents
    num_query_components = len(urllib.parse.parse_qs(query_part)) if query_part else 0
    
    # 12. NumAmpersand
    num_ampersand = url_lower.count('&')
    
    # 13. NumHash
    num_hash = url_lower.count('#')
    
    # 14. NumNumericChars
    num_numeric_chars = sum(c.isdigit() for c in url_lower)
    
    # 15. NoHttps
    no_https = 0 if url_lower.startswith('https://') else 1
    
    # 16. RandomString
    url_without_protocol = url_lower.replace('http://', '').replace('https://', '')
    entropy = calculate_entropy(url_without_protocol)
    random_string = 1 if entropy > 4.2 else 0
    
    # 17. IpAddress
    ip_address = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain_part) else 0
    
    # 18. HostnameLength
    hostname_length = len(domain_part)
    
    # 19. PathLength
    path_length = len(path_part)
    
    # 20. QueryLength
    query_length = len(query_part)
    
    # 21. DoubleSlashInPath
    double_slash_in_path = 1 if '//' in path_part else 0

    return {
        'NumDots': num_dots,
        'SubdomainLevel': subdomain_level,
        'PathLevel': path_level,
        'UrlLength': url_length,
        'NumDash': num_dash,
        'NumDashInHostname': num_dash_in_hostname,
        'AtSymbol': at_symbol,
        'TildeSymbol': tilde_symbol,
        'NumUnderscore': num_underscore,
        'NumPercent': num_percent,
        'NumQueryComponents': num_query_components,
        'NumAmpersand': num_ampersand,
        'NumHash': num_hash,
        'NumNumericChars': num_numeric_chars,
        'NoHttps': no_https,
        'RandomString': random_string,
        'IpAddress': ip_address,
        'HostnameLength': hostname_length,
        'PathLength': path_length,
        'QueryLength': query_length,
        'DoubleSlashInPath': double_slash_in_path,
        'Extra_Entropy': entropy # Retained for our own thresholding logic if needed
    }

# feature regex update 79366
