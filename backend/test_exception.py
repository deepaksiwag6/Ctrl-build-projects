from fastapi.testclient import TestClient
from main import app
import traceback
import sys

print("Starting direct testing...", flush=True)
try:
    client = TestClient(app)
    response = client.post("/api/scan-url", json={"url": "https://antigravity.google/changelog"})
    print("STATUS:", response.status_code)
    print("JSON:", response.json())
except Exception as e:
    print("EXCEPTION OCCURRED:", e)
    traceback.print_exc()
