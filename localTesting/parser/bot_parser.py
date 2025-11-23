#!/usr/bin/env python3
"""
Bot Traffic Parser
Tails nginx logs and classifies bot traffic
"""

import re
import json
import time
import sqlite3
from datetime import datetime
from pathlib import Path

# Configuration
LOG_FILE = "/logs/access.log"
DB_FILE = "/data/bot_data.db"
SIGNATURES_FILE = "bot_signatures.json"

# Load bot signatures from JSON
def load_signatures():
    """Load bot user-agent patterns from JSON file"""
    with open(SIGNATURES_FILE, 'r') as f:
        return json.load(f)

# Initialize SQLite database
def init_db():
    """Create SQLite table for bot traffic data"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bot_traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            user_agent TEXT,
            path TEXT,
            status INTEGER,
            category TEXT,
            referer TEXT
        )
    ''')
    conn.commit()
    return conn

# Classify bot based on user-agent
def classify_bot(user_agent, signatures):
    """Match user-agent against known bot patterns"""
    user_agent_lower = user_agent.lower()
    
    for category, patterns in signatures.items():
        for pattern in patterns:
            if pattern.lower() in user_agent_lower:
                return category
    
    return "unknown"

# Parse nginx log line
def parse_log_line(line):
    """Extract fields from nginx log entry"""
    # Pattern matches nginx detailed log format
    pattern = r'(\S+) - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
    match = re.match(pattern, line)
    
    if match:
        return {
            'ip': match.group(1),
            'timestamp': match.group(2),
            'request': match.group(3),
            'status': int(match.group(4)),
            'referer': match.group(6),
            'user_agent': match.group(7)
        }
    return None

# Extract path from request string
def extract_path(request):
    """Get URL path from 'GET /path HTTP/1.1' format"""
    parts = request.split()
    return parts[1] if len(parts) > 1 else "/"

# Tail log file and process entries
def tail_logs(conn, signatures):
    """Follow log file and process new entries in real-time"""
    cursor = conn.cursor()
    
    # Wait for log file to exist
    while not Path(LOG_FILE).exists():
        time.sleep(1)
    
    print(f"Monitoring {LOG_FILE}...")
    
    with open(LOG_FILE, 'r') as f:
        # Move to end of file
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            # Parse and classify
            entry = parse_log_line(line)
            if entry:
                path = extract_path(entry['request'])
                category = classify_bot(entry['user_agent'], signatures)
                
                # Store in database
                cursor.execute('''
                    INSERT INTO bot_traffic (timestamp, ip, user_agent, path, status, category, referer)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    entry['timestamp'],
                    entry['ip'],
                    entry['user_agent'],
                    path,
                    entry['status'],
                    category,
                    entry['referer']
                ))
                conn.commit()
                
                # Minimal output - only show bot category and path
                if category != "unknown":
                    print(f"[{category}] {path} - {entry['ip']}")

# Main execution
def main():
    """Initialize components and start monitoring"""
    print("Bot Traffic Monitor Starting...")
    print("Monitoring localhost:8080\n")
    
    # Initialize database and load signatures
    conn = init_db()
    signatures = load_signatures()
    
    # Start monitoring logs
    try:
        tail_logs(conn, signatures)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        conn.close()

if __name__ == "__main__":
    main()

