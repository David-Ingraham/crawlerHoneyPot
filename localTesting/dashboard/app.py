#!/usr/bin/env python3
"""
Honeypot Dashboard
Real-time visualization with on-the-fly traffic classification
"""

from flask import Flask, render_template, jsonify, Response
import sqlite3
from datetime import datetime, timedelta
from collections import Counter
import os
import requests
import csv
from io import StringIO
from classifier import classify_traffic, classify_entries, classify_traffic_detailed
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Configure rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per hour"],
    storage_uri="memory://"
)

# Database path
DB_PATH = os.getenv('DB_PATH', '/data/bot_data.db')

# Get ipinfo.io API token from environment
IPINFO_TOKEN = os.getenv('IPINFO_TOKEN', '')

# In-memory cache for IP geolocation data
geo_cache = {}

def get_db():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def dict_from_row(row):
    """Convert sqlite Row to dict"""
    return dict(zip(row.keys(), row))

def get_ip_geolocation(ip):
    """Fetch IP geolocation: memory → database → API (read-only dashboard)"""
    # Check in-memory cache first (fastest)
    if ip in geo_cache:
        return geo_cache[ip]
    
    # Check database second (no API call needed for existing IPs)
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ip, latitude, longitude, city, region, country, 
                   org, hostname, postal, timezone
            FROM ip_geolocation 
            WHERE ip = ?
        """, (ip,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            result = dict_from_row(row)
            result['loc'] = f"{result['latitude']},{result['longitude']}"
            geo_cache[ip] = result
            return result
    except Exception as e:
        print(f"Database lookup error for {ip}: {e}")
    
    # Fallback to API for new IPs not in database
    try:
        headers = {}
        if IPINFO_TOKEN:
            headers['Authorization'] = f'Bearer {IPINFO_TOKEN}'
        
        response = requests.get(f'https://ipinfo.io/{ip}/json', headers=headers, timeout=3)
        data = response.json()
        
        # Check if we got an error response
        if 'error' in data:
            print(f"ipinfo.io error for {ip}: {data['error']}")
            return None
        
        # Parse coordinates
        loc = data.get('loc', '0,0')
        if ',' in loc:
            lat, lng = loc.split(',')
            lat, lng = float(lat), float(lng)
        else:
            lat, lng = 0.0, 0.0
        
        result = {
            'ip': ip,
            'latitude': lat,
            'longitude': lng,
            'city': data.get('city'),
            'region': data.get('region'),
            'country': data.get('country'),
            'org': data.get('org'),
            'hostname': data.get('hostname'),
            'loc': data.get('loc'),
            'postal': data.get('postal'),
            'timezone': data.get('timezone')
        }
        
        # Store in memory cache only (dashboard is read-only)
        geo_cache[ip] = result
        return result
        
    except Exception as e:
        print(f"Error fetching geolocation for {ip}: {e}")
        return None

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/about')
def about():
    """About page explaining the project"""
    return render_template('about.html')

@app.route('/api/stats')
@limiter.limit("30 per minute")
def get_stats():
    """Get overall statistics with on-the-fly classification"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Total requests
    cursor.execute("SELECT COUNT(*) as total FROM bot_traffic")
    total = cursor.fetchone()['total']
    
    # Unique IPs
    cursor.execute("SELECT COUNT(DISTINCT ip) as unique_ips FROM bot_traffic")
    unique_ips = cursor.fetchone()['unique_ips']
    
    # Requests in last 24 hours
    cursor.execute("SELECT timestamp FROM bot_traffic")
    all_timestamps = cursor.fetchall()
    
    last_24h_count = 0
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=24)
    
    for row in all_timestamps:
        try:
            # Parse nginx timestamp format: "26/Nov/2025:01:04:36 +0000"
            ts_str = row['timestamp'].split()[0]
            ts = datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S')
            if ts >= cutoff:
                last_24h_count += 1
        except:
            continue
    
    # Get all entries for classification (or sample if too large)
    # Get recent entries (matches other endpoints for consistency)
    cursor.execute("SELECT user_agent, path FROM bot_traffic ORDER BY id DESC LIMIT 5000")
    entries = [dict_from_row(row) for row in cursor.fetchall()]
    
    # Classify and aggregate
    threat_levels = Counter()
    categories = Counter()
    
    for entry in entries:
        category, threat_level, _ = classify_traffic(entry['user_agent'], entry['path'])
        threat_levels[threat_level] += 1
        categories[category] += 1
    
    conn.close()
    
    # Convert to list format
    threat_level_list = [{'name': k, 'count': v} for k, v in threat_levels.most_common()]
    category_list = [{'name': k, 'count': v} for k, v in categories.most_common(10)]
    
    return jsonify({
        'total_requests': total,
        'unique_ips': unique_ips,
        'today': last_24h_count,
        'threat_levels': threat_level_list,
        'categories': category_list
    })

@app.route('/api/threat-distribution')
@limiter.limit("30 per minute")
def get_threat_distribution():
    """Get traffic distribution by threat level with percentages"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get all entries
    cursor.execute("SELECT user_agent, path FROM bot_traffic ORDER BY id DESC LIMIT 5000")
    entries = [dict_from_row(row) for row in cursor.fetchall()]
    
    # Classify and count
    threat_counts = Counter()
    threat_scores = {}
    
    for entry in entries:
        _, threat_level, threat_score = classify_traffic(entry['user_agent'], entry['path'])
        threat_counts[threat_level] += 1
        if threat_level not in threat_scores:
            threat_scores[threat_level] = []
        threat_scores[threat_level].append(threat_score)
    
    total = sum(threat_counts.values())
    
    # Build result
    results = []
    for threat_level, count in threat_counts.items():
        avg_score = sum(threat_scores[threat_level]) / len(threat_scores[threat_level])
        results.append({
            'threat_level': threat_level,
            'count': count,
            'percentage': round((count / total * 100), 1) if total > 0 else 0,
            'avg_score': round(avg_score, 1)
        })
    
    conn.close()
    return jsonify(results)

@app.route('/api/top-ips')
@limiter.limit("30 per minute")
def get_top_ips():
    """Get top requesting IPs"""
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
@limiter.limit("30 per minute")
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
@limiter.limit("30 per minute")
def get_timeline():
    """Get requests over time with configurable time range"""
    from flask import request
    days = request.args.get('days', 7, type=int)
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get records grouped by hour, using id for chronological ordering
    if days == 0:  # All time
        cursor.execute("""
            SELECT 
                substr(timestamp, 1, 17) as hour,
                COUNT(*) as count,
                MIN(id) as first_id
            FROM bot_traffic
            GROUP BY hour
            ORDER BY first_id ASC
        """)
    else:
        # Get the cutoff ID for the time range
        # First, get total record count
        cursor.execute("SELECT MAX(id) FROM bot_traffic")
        max_id = cursor.fetchone()['MAX(id)'] or 0
        
        # Estimate records per day and calculate cutoff
        # Use 2x the expected records to handle sparse data
        cursor.execute("SELECT COUNT(*) FROM bot_traffic")
        total_records = cursor.fetchone()['COUNT(*)']
        
        # Get earliest ID in our dataset
        cursor.execute("SELECT MIN(id) FROM bot_traffic")
        min_id = cursor.fetchone()['MIN(id)'] or 0
        
        # Calculate approximate cutoff ID for the time range
        # Using a buffer to ensure we get the full time range
        records_estimate = int((total_records / 31) * days * 1.3)  # Assume ~31 days of data, 1.3x buffer
        cutoff_id = max(min_id, max_id - records_estimate)
        
        cursor.execute("""
            SELECT 
                substr(timestamp, 1, 17) as hour,
                COUNT(*) as count,
                MIN(id) as first_id
            FROM bot_traffic
            WHERE id >= ?
            GROUP BY hour
            ORDER BY first_id ASC
        """, (cutoff_id,))
    
    timeline = [{'time': row['hour'], 'count': row['count']} 
                for row in cursor.fetchall()]
    
    conn.close()
    
    return jsonify(timeline)

@app.route('/api/recent')
@limiter.limit("30 per minute")
def get_recent():
    """Get most recent requests with on-the-fly classification"""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT timestamp, ip, path, user_agent
        FROM bot_traffic 
        ORDER BY id DESC 
        LIMIT 20
    """)
    
    entries = [dict_from_row(row) for row in cursor.fetchall()]
    
    # Classify each entry
    recent = []
    for entry in entries:
        category, threat_level, _ = classify_traffic(entry['user_agent'], entry['path'])
        user_agent_display = entry['user_agent'][:100] + '...' if len(entry['user_agent']) > 100 else entry['user_agent']
        
        recent.append({
            'timestamp': entry['timestamp'],
            'ip': entry['ip'],
            'path': entry['path'],
            'user_agent': user_agent_display,
            'category': category
        })
    
    conn.close()
    
    return jsonify(recent)

@app.route('/api/attack-types')
@limiter.limit("30 per minute")
def get_attack_types():
    """Classify patterns by type based on paths"""
    conn = get_db()
    cursor = conn.cursor()
    
    attack_patterns = {
        'PHPUnit RCE': '%phpunit%',
        'WordPress Probes': '%wp-%',
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
            results.append({'type': name, 'count': count, 'pattern': pattern})
    
    conn.close()
    
    results.sort(key=lambda x: x['count'], reverse=True)
    return jsonify(results)

@app.route('/api/malicious-activity')
@limiter.limit("30 per minute")
def get_malicious_activity():
    """Get details on malicious traffic only"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get all entries
    cursor.execute("SELECT user_agent, path FROM bot_traffic")
    entries = [dict_from_row(row) for row in cursor.fetchall()]
    
    # Filter and categorize malicious only
    malicious_categories = Counter()
    malicious_paths = {}
    
    for entry in entries:
        category, threat_level, _ = classify_traffic(entry['user_agent'], entry['path'])
        if threat_level == 'malicious':
            malicious_categories[category] += 1
            if category not in malicious_paths:
                malicious_paths[category] = []
            if len(malicious_paths[category]) < 3:
                malicious_paths[category].append(entry['path'])
    
    results = []
    for category, count in malicious_categories.most_common(10):
        results.append({
            'category': category,
            'count': count,
            'sample_paths': malicious_paths.get(category, [])
        })
    
    conn.close()
    return jsonify(results)

@app.route('/api/requests-by-threat/<threat_level>')
@limiter.limit("30 per minute")
def get_requests_by_threat(threat_level):
    """Get recent requests filtered by threat level with IP diversity"""
    # Validate threat level
    if threat_level not in ['benign', 'reconnaissance', 'malicious']:
        return jsonify({'error': 'Invalid threat level'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get recent requests with all details (larger pool for better diversity)
    cursor.execute("""
        SELECT timestamp, ip, path, user_agent, referer, status
        FROM bot_traffic 
        ORDER BY id DESC 
        LIMIT 5000
    """)
    
    entries = [dict_from_row(row) for row in cursor.fetchall()]
    conn.close()
    
    # Classify and filter with IP diversity
    filtered_results = []
    ip_count = {}
    MAX_PER_IP = 3
    MAX_TOTAL = 50
    
    for entry in entries:
        details = classify_traffic_detailed(entry['user_agent'], entry['path'])
        
        if details['threat_level'] == threat_level:
            current_ip = entry['ip']
            
            # Check if we've already added 3 from this IP
            if ip_count.get(current_ip, 0) >= MAX_PER_IP:
                continue
            
            # Add the request
            filtered_results.append({
                'timestamp': entry['timestamp'],
                'ip': entry['ip'],
                'path': entry['path'],
                'user_agent': entry['user_agent'],
                'referer': entry['referer'],
                'status': entry['status'],
                'category': details['category'],
                'threat_level': details['threat_level'],
                'threat_score': details['threat_score'],
                'matched_patterns': details['matched_patterns']
            })
            
            # Increment counter for this IP
            ip_count[current_ip] = ip_count.get(current_ip, 0) + 1
            
            # Limit to 50 total results
            if len(filtered_results) >= MAX_TOTAL:
                break
    
    return jsonify(filtered_results)

@app.route('/api/requests-by-category/<category>')
@limiter.limit("30 per minute")
def get_requests_by_category(category):
    """Get recent requests filtered by specific category with IP diversity"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get recent requests
    cursor.execute("""
        SELECT timestamp, ip, path, user_agent, referer, status
        FROM bot_traffic 
        ORDER BY id DESC 
        LIMIT 5000
    """)
    
    entries = [dict_from_row(row) for row in cursor.fetchall()]
    conn.close()
    
    # Classify and filter by category
    filtered_results = []
    ip_count = {}
    MAX_PER_IP = 3
    MAX_TOTAL = 50
    
    for entry in entries:
        details = classify_traffic_detailed(entry['user_agent'], entry['path'])
        
        if details['category'] == category:
            current_ip = entry['ip']
            
            if ip_count.get(current_ip, 0) >= MAX_PER_IP:
                continue
            
            filtered_results.append({
                'timestamp': entry['timestamp'],
                'ip': entry['ip'],
                'path': entry['path'],
                'user_agent': entry['user_agent'],
                'referer': entry['referer'],
                'status': entry['status'],
                'category': details['category'],
                'threat_level': details['threat_level'],
                'threat_score': details['threat_score'],
                'matched_patterns': details['matched_patterns']
            })
            
            ip_count[current_ip] = ip_count.get(current_ip, 0) + 1
            
            if len(filtered_results) >= MAX_TOTAL:
                break
    
    return jsonify(filtered_results)

@app.route('/api/requests-by-ip/<ip>')
@limiter.limit("30 per minute")
def get_requests_by_ip(ip):
    """Get recent requests from a specific IP"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get requests from this IP
    cursor.execute("""
        SELECT timestamp, ip, path, user_agent, referer, status
        FROM bot_traffic 
        WHERE ip = ?
        ORDER BY id DESC 
        LIMIT 50
    """, (ip,))
    
    entries = [dict_from_row(row) for row in cursor.fetchall()]
    conn.close()
    
    # Classify each entry
    results = []
    for entry in entries:
        details = classify_traffic_detailed(entry['user_agent'], entry['path'])
        results.append({
            'timestamp': entry['timestamp'],
            'ip': entry['ip'],
            'path': entry['path'],
            'user_agent': entry['user_agent'],
            'referer': entry['referer'],
            'status': entry['status'],
            'category': details['category'],
            'threat_level': details['threat_level'],
            'threat_score': details['threat_score'],
            'matched_patterns': details['matched_patterns']
        })
    
    return jsonify(results)

@app.route('/api/requests-by-path')
@limiter.limit("30 per minute")
def get_requests_by_path():
    """Get recent requests to a specific path (path passed as query parameter)"""
    from flask import request
    path = request.args.get('path', '')
    
    if not path:
        return jsonify({'error': 'Path parameter required'}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get requests to this path with IP diversity
    cursor.execute("""
        SELECT timestamp, ip, path, user_agent, referer, status
        FROM bot_traffic 
        WHERE path = ?
        ORDER BY id DESC 
        LIMIT 200
    """, (path,))
    
    entries = [dict_from_row(row) for row in cursor.fetchall()]
    conn.close()
    
    # Apply IP diversity
    filtered_results = []
    ip_count = {}
    MAX_PER_IP = 3
    MAX_TOTAL = 50
    
    for entry in entries:
        current_ip = entry['ip']
        
        if ip_count.get(current_ip, 0) >= MAX_PER_IP:
            continue
        
        details = classify_traffic_detailed(entry['user_agent'], entry['path'])
        filtered_results.append({
            'timestamp': entry['timestamp'],
            'ip': entry['ip'],
            'path': entry['path'],
            'user_agent': entry['user_agent'],
            'referer': entry['referer'],
            'status': entry['status'],
            'category': details['category'],
            'threat_level': details['threat_level'],
            'threat_score': details['threat_score'],
            'matched_patterns': details['matched_patterns']
        })
        
        ip_count[current_ip] = ip_count.get(current_ip, 0) + 1
        
        if len(filtered_results) >= MAX_TOTAL:
            break
    
    return jsonify(filtered_results)

@app.route('/api/requests-by-pattern')
@limiter.limit("30 per minute")
def get_requests_by_pattern():
    """Get recent requests matching a pattern (pattern passed as query parameter)"""
    from flask import request
    pattern = request.args.get('pattern', '')
    
    if not pattern:
        return jsonify({'error': 'Pattern parameter required'}), 400
    

    conn = get_db()
    cursor = conn.cursor()
    
    # Get requests matching the pattern
    cursor.execute("""
        SELECT timestamp, ip, path, user_agent, referer, status
        FROM bot_traffic 
        WHERE path LIKE ?
        ORDER BY id DESC 
        LIMIT 500
    """, (pattern,))
    
    entries = [dict_from_row(row) for row in cursor.fetchall()]
    conn.close()
    
    # Apply IP diversity
    filtered_results = []
    ip_count = {}
    MAX_PER_IP = 3
    MAX_TOTAL = 50
    
    for entry in entries:
        current_ip = entry['ip']
        
        if ip_count.get(current_ip, 0) >= MAX_PER_IP:
            continue
        
        details = classify_traffic_detailed(entry['user_agent'], entry['path'])
        filtered_results.append({
            'timestamp': entry['timestamp'],
            'ip': entry['ip'],
            'path': entry['path'],
            'user_agent': entry['user_agent'],
            'referer': entry['referer'],
            'status': entry['status'],
            'category': details['category'],
            'threat_level': details['threat_level'],
            'threat_score': details['threat_score'],
            'matched_patterns': details['matched_patterns']
        })
        
        ip_count[current_ip] = ip_count.get(current_ip, 0) + 1
        
        if len(filtered_results) >= MAX_TOTAL:
            break
    
    return jsonify(filtered_results)

@app.route('/api/ipinfo/<ip>')
@limiter.limit("30 per minute")
def get_ipinfo(ip):
    """Proxy endpoint for IP geolocation with Bearer token authentication"""
    data = get_ip_geolocation(ip)
    if data:
        return jsonify(data)
    return jsonify({'error': 'Could not fetch IP information'}), 404

@app.route('/api/geo-locations')
@limiter.limit("5 per minute")
def get_geo_locations():
    """Get geographic distribution of traffic from database"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Join traffic counts with geolocation data
    cursor.execute("""
        SELECT 
            g.ip, 
            g.latitude as lat, 
            g.longitude as lng,
            g.city, 
            g.country,
            COUNT(t.ip) as count
        FROM ip_geolocation g
        JOIN bot_traffic t ON g.ip = t.ip
        WHERE g.latitude != 0 AND g.longitude != 0
        GROUP BY g.ip
        HAVING count > 2
        ORDER BY count DESC
        LIMIT 500
    """)
    
    results = [dict_from_row(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(results)

@app.route('/api/download-dataset')
@limiter.limit("3 per hour")
def download_dataset():
    """Download full dataset as CSV"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Get all data
    cursor.execute("""
        SELECT id, timestamp, ip, user_agent, path, status, referer
        FROM bot_traffic 
        ORDER BY id DESC
    """)
    
    rows = cursor.fetchall()
    conn.close()
    
    # Create CSV in memory
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['id', 'timestamp', 'ip', 'user_agent', 'path', 'status', 'referer'])
    
    # Write data
    for row in rows:
        writer.writerow([
            row['id'],
            row['timestamp'],
            row['ip'],
            row['user_agent'],
            row['path'],
            row['status'],
            row['referer']
        ])
    
    # Prepare response
    output.seek(0)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=honeypot_data_{datetime.now().strftime("%Y%m%d")}.csv'
        }
    )

if __name__ == '__main__':
    port = int(os.getenv('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
