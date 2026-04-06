import sys
from api.routes import scan_url, ScanURLRequest
import database
from sqlalchemy.orm import Session

db = next(database.get_db())

req = ScanURLRequest(url="https://antigravity.google/changelog")

try:
    res = scan_url(req, db)
    print("SUCCESS")
    print(res)
except Exception as e:
    import traceback
    traceback.print_exc()
