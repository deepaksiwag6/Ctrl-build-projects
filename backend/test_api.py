import json
import urllib.request
import urllib.error

url = "http://127.0.0.1:8000/api/scan-url"
data = json.dumps({"url": "https://antigravity.google/changelog"}).encode('utf-8')
headers = {'Content-Type': 'application/json'}

req = urllib.request.Request(url, data=data, headers=headers)

try:
    with urllib.request.urlopen(req) as res:
        print("SUCCESS:")
        print(res.read().decode())
except urllib.error.HTTPError as e:
    print(f"HTTP ERROR {e.code}:")
    print(e.read().decode())
except Exception as e:
    print(f"ERROR: {e}")
