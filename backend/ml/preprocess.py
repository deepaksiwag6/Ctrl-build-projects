"""
preprocess.py – Feature engineering for PhishShield ML pipeline.

Two modes:
  1. Batch: preprocess_dataset() reads the existing dataset.csv (which already
     contains pre-computed Kaggle columns + CLASS_LABEL) and passes it straight
     through so train_model.py can consume it unchanged.

  2. Real-time: preprocess_single_url(url) extracts the same 21 Kaggle-style
     lexical features from any raw URL string, used by the /scan-url API route.
"""

import os
import re
import math
import pandas as pd
import urllib.parse
from collections import Counter

# ── Paths ──────────────────────────────────────────────────────────────────────
DATASET_PATH = os.path.join(os.path.dirname(__file__), '..', 'dataset.csv')
PROCESSED_PATH = os.path.join(os.path.dirname(__file__), 'processed_dataset.csv')

# Features kept for training / inference (must match what train_model.py uses)
FEATURE_COLUMNS = [
    'NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
    'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
    'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
    'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
    'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath',
]

# ── Helpers ────────────────────────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    p = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in p.values())


def preprocess_single_url(url: str) -> dict:
    """Extract the 21 Kaggle-style lexical features from a single raw URL."""
    url_l = url.lower()
    if not url_l.startswith('http'):
        url_l = 'http://' + url_l

    parsed = urllib.parse.urlparse(url_l)
    domain = parsed.netloc.split(':')[0]
    path   = parsed.path
    query  = parsed.query

    no_https   = 0 if url_l.startswith('https://') else 1
    raw_url    = url_l.replace('http://', '').replace('https://', '')
    rand_str   = 1 if _entropy(raw_url) > 4.2 else 0
    ip_address = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0

    return {
        'NumDots':            url_l.count('.'),
        'SubdomainLevel':     max(0, domain.count('.') - 1),
        'PathLevel':          max(0, path.count('/') - (1 if path.endswith('/') else 0)),
        'UrlLength':          len(url_l),
        'NumDash':            url_l.count('-'),
        'NumDashInHostname':  domain.count('-'),
        'AtSymbol':           1 if '@' in url_l else 0,
        'TildeSymbol':        1 if '~' in url_l else 0,
        'NumUnderscore':      url_l.count('_'),
        'NumPercent':         url_l.count('%'),
        'NumQueryComponents': len(urllib.parse.parse_qs(query)) if query else 0,
        'NumAmpersand':       url_l.count('&'),
        'NumHash':            url_l.count('#'),
        'NumNumericChars':    sum(c.isdigit() for c in url_l),
        'NoHttps':            no_https,
        'RandomString':       rand_str,
        'IpAddress':          ip_address,
        'HostnameLength':     len(domain),
        'PathLength':         len(path),
        'QueryLength':        len(query),
        'DoubleSlashInPath':  1 if '//' in path else 0,
    }


# ── Batch preprocessing ────────────────────────────────────────────────────────

def preprocess_dataset(input_path: str = DATASET_PATH,
                       output_path: str = PROCESSED_PATH) -> str:
    """
    The dataset.csv already contains the 21 Kaggle feature columns + CLASS_LABEL.
    We just select the needed columns and write processed_dataset.csv.
    """
    df = pd.read_csv(input_path)

    if 'CLASS_LABEL' not in df.columns:
        raise ValueError("dataset.csv must have a CLASS_LABEL column.")

    missing = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"dataset.csv is missing columns: {missing}")

    result = df[FEATURE_COLUMNS + ['CLASS_LABEL']].copy()
    result.to_csv(output_path, index=False)
    print(f"[preprocess] Saved {len(result)} rows → {output_path}")
    return output_path


if __name__ == '__main__':
    preprocess_dataset()
