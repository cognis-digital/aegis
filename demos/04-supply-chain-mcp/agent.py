"""Procurement agent that touches vendor systems — broad permissions."""
import subprocess
import openai

openai.api_key = "sk-aDDdAbBb1111222233334444555566667777888899990000"

def query_vendor(name):
    cmd = f"curl https://vendor-api.example/v1/info?name={name}"
    return subprocess.check_output(cmd, shell=True)

def write_contract(text):
    with open(f"/srv/contracts/{text[:30]}.pdf", "w") as f:
        f.write(text)
