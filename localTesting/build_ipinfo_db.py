#!/usr/bin/env python3
"""
Build IP Geolocation Database
Fetches geolocation data for all unique IPs in bot_traffic table
"""

import sqlite3
import requests
import time
import os

# Configuration
DB_PATH = 'data/bot_data.db'
IPINFO_TOKEN = os.getenv('IPINFO_TOKEN', '')

if not IPINFO_TOKEN:
    print("ERROR: IPINFO_TOKEN environment variable not set")
    print("Run: export IPINFO_TOKEN=your_token_here")
    exit(1)

def create_geolocation_table(conn):
    """Create table for IP geolocation data"""
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_geolocation (
            ip TEXT PRIMARY KEY,
            latitude REAL,
            longitude REAL,
            city TEXT,
            region TEXT,
            country TEXT,
            org TEXT,
            hostname TEXT,
            postal TEXT,
            timezone TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    print("Created ip_geolocation table")

def get_unique_ips(conn):
    """Get all unique IPs from bot_traffic"""
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT ip FROM bot_traffic ORDER BY ip")
    ips = [row[0] for row in cursor.fetchall()]
    print(f"Found {len(ips)} unique IPs")
    return ips

def fetch_geolocation(ip):
    """Fetch geolocation data from ipinfo.io"""
    headers = {'Authorization': f'Bearer {IPINFO_TOKEN}'}
    
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json', headers=headers, timeout=5)
        data = response.json()
        
        if 'error' in data:
            print(f"  ERROR: {data['error']}")
            return None
        
        # Parse coordinates
        loc = data.get('loc', '0,0')
        if ',' in loc:
            lat, lng = loc.split(',')
            lat, lng = float(lat), float(lng)
        else:
            lat, lng = 0.0, 0.0
        
        return {
            'ip': ip,
            'latitude': lat,
            'longitude': lng,
            'city': data.get('city'),
            'region': data.get('region'),
            'country': data.get('country'),
            'org': data.get('org'),
            'hostname': data.get('hostname'),
            'postal': data.get('postal'),
            'timezone': data.get('timezone')
        }
        
    except Exception as e:
        print(f"  ERROR: {e}")
        return None

def store_geolocation(conn, geo_data):
    """Store geolocation data in database"""
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR REPLACE INTO ip_geolocation 
        (ip, latitude, longitude, city, region, country, org, hostname, postal, timezone)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        geo_data['ip'],
        geo_data['latitude'],
        geo_data['longitude'],
        geo_data['city'],
        geo_data['region'],
        geo_data['country'],
        geo_data['org'],
        geo_data['hostname'],
        geo_data['postal'],
        geo_data['timezone']
    ))
    conn.commit()

def main():
    """Main execution"""
    print("Starting IP Geolocation Database Build")
    print("=" * 50)
    
    # Connect to database
    conn = sqlite3.connect(DB_PATH)
    
    # Create table
    create_geolocation_table(conn)
    
    # Get unique IPs
    ips = get_unique_ips(conn)
    
    # Check for existing entries
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM ip_geolocation")
    existing = cursor.fetchone()[0]
    print(f"Already have {existing} IPs in database")
    
    # Fetch geolocation for each IP
    success_count = 0
    error_count = 0
    skipped_count = 0
    
    for i, ip in enumerate(ips, 1):
        # Check if already exists
        cursor.execute("SELECT ip FROM ip_geolocation WHERE ip = ?", (ip,))
        if cursor.fetchone():
            skipped_count += 1
            if i % 50 == 0:
                print(f"Progress: {i}/{len(ips)} (skipped {skipped_count}, success {success_count}, errors {error_count})")
            continue
        
        print(f"[{i}/{len(ips)}] Fetching {ip}...", end=' ')
        
        geo_data = fetch_geolocation(ip)
        
        if geo_data:
            store_geolocation(conn, geo_data)
            success_count += 1
            print(f"✓ {geo_data.get('city', 'Unknown')}, {geo_data.get('country', 'Unknown')}")
        else:
            error_count += 1
            print("✗ Failed")
        
        # Rate limiting: 50k/month = ~1600/day = ~1/second is safe
        time.sleep(0.5)
    
    conn.close()
    
    print("\n" + "=" * 50)
    print("Build Complete!")
    print(f"Total IPs: {len(ips)}")
    print(f"Skipped (already in DB): {skipped_count}")
    print(f"Successfully fetched: {success_count}")
    print(f"Errors: {error_count}")

if __name__ == '__main__':
    main()

