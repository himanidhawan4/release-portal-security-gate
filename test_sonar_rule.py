import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

token = os.getenv("SONAR_TOKEN")

if not token:
    print("SONAR_TOKEN is not configured.")
    exit(1)

rule_key = "text:S8564"
organization = "himanidhawan4"

url = "https://sonarcloud.io/api/rules/show"

response = requests.get(
    url,
    params={
        "key": rule_key,
        "organization": organization,
    },
    auth=(token, ""),
    timeout=20,
)

print("HTTP STATUS:", response.status_code)
print()

try:
    data = response.json()
    print(json.dumps(data, indent=2))
except Exception:
    print(response.text)
