"""
Honeypot chat agent: SQL tools plus Python classification aligned with the dashboard.
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from typing import Any

from langchain.agents import create_agent
from langchain_community.agent_toolkits.sql.toolkit import SQLDatabaseToolkit
from langchain_community.utilities import SQLDatabase
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.tools import tool
from langchain_groq import ChatGroq

from classifier import classify_traffic

_MAX_SAMPLE = 20000
_DEFAULT_SAMPLE = 5000


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1",
        (name,),
    ).fetchone()
    return row is not None


def _clamp_limit(row_limit: int) -> int:
    if row_limit < 1:
        return _DEFAULT_SAMPLE
    return min(int(row_limit), _MAX_SAMPLE)


def _final_message_text(msg: BaseMessage) -> str:
    c = msg.content
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        parts: list[str] = []
        for block in c:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                parts.append(str(block.get("text", "")))
        return "".join(parts)
    return str(c)


def _build_geo_map(conn: sqlite3.Connection, ips: list[str]) -> dict[str, str]:
    if not ips or not _table_exists(conn, "ip_geolocation"):
        return {}
    out: dict[str, str] = {}
    chunk = 400
    for i in range(0, len(ips), chunk):
        part = ips[i : i + chunk]
        placeholders = ",".join("?" * len(part))
        q = f"SELECT ip, country FROM ip_geolocation WHERE ip IN ({placeholders})"
        for row in conn.execute(q, part).fetchall():
            if row[0] and row[1]:
                out[row[0]] = row[1]
    return out


def make_classified_analytics_tool(db_path: str):
    """Tool factory: classifier + optional ip_geolocation join (same semantics as dashboard sample)."""

    @tool
    def honeypot_classified_analytics(task: str, row_limit: int = _DEFAULT_SAMPLE) -> str:
        """Run the dashboard threat classifier on recent bot_traffic rows (not available via raw SQL).

        Use this when the user asks about benign / reconnaissance / malicious counts, or malicious (or
        other threat levels) broken down by country. Threat labels are computed in Python from
        user_agent and path; they are not columns in the database.

        Args:
            task: One of:
                - threat_counts_in_sample: counts per threat_level for the most recent rows (like dashboard cards when row_limit=5000).
                - malicious_top_countries: among malicious requests in the sample, tally by country (requires ip_geolocation populated).
                - recon_top_countries: among reconnaissance requests, tally by country.
                - benign_top_countries: among benign requests, tally by country.
            row_limit: How many most recent bot_traffic rows to scan (default 5000, max 20000).

        Returns:
            JSON string with counts and notes (missing geo, table missing, etc.).
        """
        lim = _clamp_limit(row_limit)
        task_key = (task or "").strip().lower().replace(" ", "_").replace("-", "_")

        conn = sqlite3.connect(db_path)
        try:
            if not _table_exists(conn, "bot_traffic"):
                return json.dumps({"error": "bot_traffic table not found"})

            cur = conn.execute(
                """
                SELECT ip, user_agent, path
                FROM bot_traffic
                ORDER BY id DESC
                LIMIT ?
                """,
                (lim,),
            )
            rows = cur.fetchall()
            if not rows:
                return json.dumps(
                    {"error": "no rows in bot_traffic", "row_limit_requested": lim}
                )

            if task_key in ("threat_counts", "threat_counts_in_sample", "threat_summary"):
                counts: Counter[str] = Counter()
                for ip, ua, path in rows:
                    _, level, _ = classify_traffic(ua or "", path or "")
                    counts[level] += 1
                return json.dumps(
                    {
                        "task": "threat_counts_in_sample",
                        "rows_scanned": len(rows),
                        "row_limit": lim,
                        "threat_level_counts": dict(counts),
                        "note": "Classifier matches dashboard /api/stats sample when row_limit=5000.",
                    },
                    indent=2,
                )

            if task_key in (
                "malicious_top_countries",
                "malicious_by_country",
                "top_malicious_countries",
            ):
                if not _table_exists(conn, "ip_geolocation"):
                    return json.dumps(
                        {
                            "error": "ip_geolocation table missing",
                            "hint": "Populate geo with build_ipinfo_db or equivalent; SQL cannot infer country from IP alone here.",
                        }
                    )
                ips_unique: list[str] = []
                seen: set[str] = set()
                malicious_rows: list[tuple[str, str, str]] = []
                for ip, ua, path in rows:
                    _, level, _ = classify_traffic(ua or "", path or "")
                    if level != "malicious":
                        continue
                    malicious_rows.append((ip or "", ua or "", path or ""))
                    if ip and ip not in seen:
                        seen.add(ip)
                        ips_unique.append(ip)
                geo = _build_geo_map(conn, ips_unique)
                by_country: Counter[str] = Counter()
                no_geo = 0
                for ip, _, _ in malicious_rows:
                    ctry = geo.get(ip) if ip else None
                    if not ctry:
                        no_geo += 1
                        by_country["(no country in ip_geolocation)"] += 1
                    else:
                        by_country[ctry] += 1
                top = by_country.most_common(15)
                return json.dumps(
                    {
                        "task": "malicious_top_countries",
                        "rows_in_sample": len(rows),
                        "malicious_requests_in_sample": len(malicious_rows),
                        "row_limit": lim,
                        "top_countries": [{"country": k, "count": v} for k, v in top],
                        "unique_ips_malicious": len(ips_unique),
                        "malicious_requests_without_country_row": no_geo,
                    },
                    indent=2,
                )

            if task_key in ("recon_top_countries", "reconnaissance_top_countries"):
                if not _table_exists(conn, "ip_geolocation"):
                    return json.dumps({"error": "ip_geolocation table missing"})
                ips_unique = []
                seen = set()
                matched: list[str] = []
                for ip, ua, path in rows:
                    _, level, _ = classify_traffic(ua or "", path or "")
                    if level != "reconnaissance":
                        continue
                    if ip and ip not in seen:
                        seen.add(ip)
                        ips_unique.append(ip)
                    matched.append(ip or "")
                geo = _build_geo_map(conn, ips_unique)
                by_country: Counter[str] = Counter()
                for ip in matched:
                    ctry = geo.get(ip) if ip else None
                    if not ctry:
                        by_country["(no country in ip_geolocation)"] += 1
                    else:
                        by_country[ctry] += 1
                top = by_country.most_common(15)
                return json.dumps(
                    {
                        "task": "recon_top_countries",
                        "rows_scanned": len(rows),
                        "reconnaissance_requests": len(matched),
                        "row_limit": lim,
                        "top_countries": [{"country": k, "count": v} for k, v in top],
                    },
                    indent=2,
                )

            if task_key in ("benign_top_countries",):
                if not _table_exists(conn, "ip_geolocation"):
                    return json.dumps({"error": "ip_geolocation table missing"})
                ips_unique = []
                seen = set()
                matched: list[str] = []
                for ip, ua, path in rows:
                    _, level, _ = classify_traffic(ua or "", path or "")
                    if level != "benign":
                        continue
                    if ip and ip not in seen:
                        seen.add(ip)
                        ips_unique.append(ip)
                    matched.append(ip or "")
                geo = _build_geo_map(conn, ips_unique)
                by_country = Counter()
                for ip in matched:
                    ctry = geo.get(ip) if ip else None
                    if not ctry:
                        by_country["(no country in ip_geolocation)"] += 1
                    else:
                        by_country[ctry] += 1
                top = by_country.most_common(15)
                return json.dumps(
                    {
                        "task": "benign_top_countries",
                        "rows_scanned": len(rows),
                        "benign_requests": len(matched),
                        "row_limit": lim,
                        "top_countries": [{"country": k, "count": v} for k, v in top],
                    },
                    indent=2,
                )

            return json.dumps(
                {
                    "error": "unknown task",
                    "task_received": task,
                    "valid_tasks": [
                        "threat_counts_in_sample",
                        "malicious_top_countries",
                        "recon_top_countries",
                        "benign_top_countries",
                    ],
                }
            )
        finally:
            conn.close()

    return honeypot_classified_analytics


SYSTEM_PROMPT = """You are an analyst for a honeypot web traffic SQLite database.

Schema:
- bot_traffic: id, timestamp, ip, user_agent, path, status, referer
- ip_geolocation: optional; ip, country, city, region, latitude, longitude, etc.

Rules:
- Columns like threat_level, malicious, or category do NOT exist. Do not assume them in SQL.
- For questions about benign / reconnaissance / malicious counts, or threat breakdown by country, you MUST call honeypot_classified_analytics with the right task. Use row_limit=5000 unless the user asks for a different sample size (max 20000).
- For totals over all rows, top paths, top IPs, time filters, status codes, use the SQL tools.
- After using tools, answer in plain English. State the sample size when answers come from classified analytics (e.g. last 5000 requests).
"""


def run_honeypot_chat(
    db_path: str,
    user_message: str,
    groq_api_key: str,
    model: str = "llama-3.3-70b-versatile",
) -> dict[str, Any]:
    """Run the agent and return answer text plus a light trace for debugging."""

    llm = ChatGroq(
        model=model,
        temperature=0,
        groq_api_key=groq_api_key,
    )
    db = SQLDatabase.from_uri(
        f"sqlite:///{db_path}",
        sample_rows_in_table_info=2,
    )
    toolkit = SQLDatabaseToolkit(db=db, llm=llm)
    sql_tools = toolkit.get_tools()
    analytics_tool = make_classified_analytics_tool(db_path)
    tools = list(sql_tools) + [analytics_tool]

    agent = create_agent(
        llm,
        tools=tools,
        system_prompt=SYSTEM_PROMPT,
    )

    result = agent.invoke(
        {"messages": [{"role": "user", "content": user_message.strip()}]}
    )
    messages = result.get("messages") or []
    answer = ""
    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and getattr(msg, "tool_calls", None):
            continue
        if isinstance(msg, AIMessage):
            t = _final_message_text(msg).strip()
            if t:
                answer = t
                break
    if not answer:
        for msg in reversed(messages):
            if isinstance(msg, AIMessage):
                t = _final_message_text(msg).strip()
                if t:
                    answer = t
                    break

    trace: list[dict[str, Any]] = []
    for msg in messages:
        name = msg.__class__.__name__
        if name == "ToolMessage":
            trace.append(
                {
                    "type": "tool_result",
                    "name": getattr(msg, "name", None),
                    "content_preview": (msg.content[:500] + "…")
                    if isinstance(msg.content, str) and len(msg.content) > 500
                    else msg.content,
                }
            )
        elif name == "AIMessage" and getattr(msg, "tool_calls", None):
            calls_out: list[dict[str, Any]] = []
            for tc in msg.tool_calls:
                if isinstance(tc, dict):
                    calls_out.append(
                        {"name": tc.get("name"), "args": tc.get("args")}
                    )
                else:
                    calls_out.append(
                        {
                            "name": getattr(tc, "name", None),
                            "args": getattr(tc, "args", None),
                        }
                    )
            trace.append({"type": "tool_calls", "calls": calls_out})

    return {"answer": answer or "(no text response)", "trace": trace}
