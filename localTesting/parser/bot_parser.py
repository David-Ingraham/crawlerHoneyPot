#!/usr/bin/env python3
"""
Bot Traffic Parser
Tails nginx logs and stores raw traffic data
"""

import re
import time
import sqlite3
from pathlib import Path

# Configuration
LOG_FILE = "/logs/access.log"
DB_FILE = "/data/bot_data.db"

# Initialize SQLite database
def init_db():
    """Create SQLite table for traffic data"""
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
            referer TEXT
        )
    ''')
    conn.commit()
    return conn

# Parse nginx log line
def parse_log_line(line):
    """Extract fields from nginx log entry"""
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
def tail_logs(conn):
    """Follow log file and store entries"""
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
            
            # Parse and store
            entry = parse_log_line(line)
            if entry:
                path = extract_path(entry['request'])
                
                # Store raw data only
                cursor.execute('''
                    INSERT INTO bot_traffic (timestamp, ip, user_agent, path, status, referer)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    entry['timestamp'],
                    entry['ip'],
                    entry['user_agent'],
                    path,
                    entry['status'],
                    entry['referer']
                ))
                conn.commit()

# Main execution
def main():
    """Initialize and start monitoring"""
    print("Bot Traffic Parser Starting...")
    
    # Initialize database
    conn = init_db()
    print("Database initialized")
    
    # Start monitoring logs
    try:
        tail_logs(conn)
    except KeyboardInterrupt:
        print("Shutting down...")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
