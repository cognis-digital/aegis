"""Internal analytics agent — uses env vars + secret manager."""
import os
from openai import OpenAI

client = OpenAI()  # reads OPENAI_API_KEY from env

AGENT_TOOLS = ["sql.query_readonly", "metrics.compute"]

def run(query: str):
    # query is validated by gateway before reaching here
    assert query.isascii() and len(query) < 2000
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role":"user","content":query}]
    )
