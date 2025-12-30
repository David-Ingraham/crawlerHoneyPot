#!/usr/bin/env python3
"""
Honeypot Dashboard
Real-time visualization of bot traffic data
"""

from flask import Flask, render_template, jsonify
import sqlite3
from datetime import datetime, timedelta
import os

app = Flask(__name__)

# Database path
DB_PATH = os.getenv('DB_PATH', '/data/bot_data.db')

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/about')
def about():
    """About page explaining the project"""
    return render_template('about.html')

@app.route('/api/stats')
def get_stats():
    """Get overall statistics"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Total requests
    cursor.execute("SELECT COUNT(*) as total FROM bot_traffic")
    total = cursor.fetchone()['total']
    
    # Unique IPs
    cursor.execute("SELECT COUNT(DISTINCT ip) as unique_ips FROM bot_traffic")
    unique_ips = cursor.fetchone()['unique_ips']
    
    # Requests today
    today = datetime.now().strftime('%d/%b/%Y')
    cursor.execute("SELECT COUNT(*) as today FROM bot_traffic WHERE timestamp LIKE ?", (f'%{today}%',))
    today_count = cursor.fetchone()['today']
    
    # Category breakdown
    cursor.execute("""
        SELECT category, COUNT(*) as count 
        FROM bot_traffic 
        GROUP BY category 
        ORDER BY count DESC
    """)
    categories = [{'name': row['category'], 'count': row['count']} for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify({
        'total_requests': total,
        'unique_ips': unique_ips,
        'today': today_count,
        'categories': categories
    })

@app.route('/api/top-ips')
def get_top_ips():
    """Get top attacking IPs"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT ip, COUNT(*) as count 
        FROM bot_traffic 
        GROUP BY ip 
        ORDER BY count DESC 
        LIMIT 10
    """)
    
    ips = [{'ip': row['ip'], 'count': row['count']} for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(ips)

@app.route('/api/top-paths')
def get_top_paths():
    """Get most targeted paths"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT path, COUNT(*) as count 
        FROM bot_traffic 
        GROUP BY path 
        ORDER BY count DESC 
        LIMIT 15
    """)
    
    paths = [{'path': row['path'], 'count': row['count']} for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(paths)

@app.route('/api/timeline')
def get_timeline():
    """Get requests over time (last 7 days by hour)"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get last 24 hours of data
    cursor.execute("""
        SELECT timestamp, COUNT(*) as count
        FROM bot_traffic
        GROUP BY substr(timestamp, 1, 17)
        ORDER BY timestamp DESC
        LIMIT 168
    """)
    
    timeline = [{'time': row['timestamp'], 'count': row['count']} for row in cursor.fetchall()]
    timeline.reverse()
    
    conn.close()
    
    return jsonify(timeline)

@app.route('/api/recent')
def get_recent():
    """Get most recent attacks"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT timestamp, ip, path, user_agent, category
        FROM bot_traffic 
        ORDER BY id DESC 
        LIMIT 20
    """)
    
    recent = [{
        'timestamp': row['timestamp'],
        'ip': row['ip'],
        'path': row['path'],
        'user_agent': row['user_agent'][:100] + '...' if len(row['user_agent']) > 100 else row['user_agent'],
        'category': row['category']
    } for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify(recent)

@app.route('/api/attack-types')
def get_attack_types():
    """Classify attacks by type based on path patterns"""
    conn = get_db()
    cursor = conn.cursor()
    
    attack_patterns = {
        'PHPUnit RCE': '%phpunit%',
        'WordPress': '%wp-%',
        'Git Exposure': '%.git%',
        'Env Files': '%.env%',
        'Config Files': '%config%',
        'Shell Injection': '%shell%',
        'SQL Injection': '%sql%',
        'Admin Panels': '%admin%',
        'API Probes': '%api%'
    }
    
    results = []
    for name, pattern in attack_patterns.items():
        cursor.execute("""
            SELECT COUNT(*) as count 
            FROM bot_traffic 
            WHERE path LIKE ?
        """, (pattern,))
        count = cursor.fetchone()['count']
        if count > 0:
            results.append({'type': name, 'count': count})
    
    conn.close()
    
    results.sort(key=lambda x: x['count'], reverse=True)
    return jsonify(results)

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=True)


