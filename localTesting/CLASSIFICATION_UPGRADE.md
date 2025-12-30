# Classification System Upgrade

## What Changed

### Enhanced Multi-Factor Traffic Classification

The honeypot now uses a sophisticated threat analysis system instead of simple user-agent matching.

## New Features

### 1. Three Threat Levels

**🟢 Benign (Score < 0)**
- Legitimate search engines (Google, Bing)
- Security research scanners (Censys, Shodan)
- SEO tools (Ahrefs, Semrush)
- Social media bots (Twitter, Reddit)

**🟡 Reconnaissance (Score 0-19)**
- Vulnerability scanning
- Credential harvesting (.env, .git files)
- Directory enumeration
- Technology fingerprinting

**🔴 Malicious (Score ≥ 20)**
- Remote code execution attempts
- Botnet recruitment (Mirai, Mozi)
- Exploit payloads
- Web shell access attempts

### 2. Multi-Factor Classification

Instead of only looking at user-agent, the system now considers:
- **User-agent patterns** - Who's making the request
- **Path patterns** - What they're requesting
- **Threat scoring** - Combined risk assessment

### 3. Enhanced Database Schema

New fields added to `bot_traffic` table:
- `threat_level` (TEXT) - benign, reconnaissance, or malicious
- `threat_score` (INTEGER) - Numerical threat assessment

## Automatic Migration

The updated `bot_parser.py` will **automatically migrate** your existing database when you restart it. Old entries will be marked as `threat_level='unknown'` with `threat_score=0`.

New traffic will be classified with the enhanced system.

## Testing the New System

### Local Testing

```bash
cd localTesting

# Stop current containers
docker-compose down

# Rebuild with new code
docker-compose up --build

# Watch parser output (shows threat levels with color indicators)
docker-compose logs -f parser
```

### Generate Test Traffic

```bash
# Benign - Search engine
curl -A "Googlebot/2.1" http://localhost/

# Reconnaissance - Looking for vulnerabilities
curl http://localhost/.env
curl http://localhost/.git/config
curl http://localhost/wp-admin/

# Malicious - Exploit attempt
curl "http://localhost/shell?cd+/tmp;wget+malware"
curl "http://localhost/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
```

### View Results

**Check database:**
```bash
# Threat distribution
sqlite3 data/bot_data.db "SELECT threat_level, COUNT(*) FROM bot_traffic GROUP BY threat_level;"

# Sample malicious traffic
sqlite3 data/bot_data.db "SELECT ip, path, threat_score FROM bot_traffic WHERE threat_level='malicious' LIMIT 10;"
```

**Check dashboard:**
- Open http://localhost:8080
- Look for new "Threat Level" cards showing distribution
- Charts now labeled more accurately ("Traffic Categories" not "Attack Categories")

## Deploying to Production

### 1. Backup Current Database

```bash
# On Linode
cd ~/crawlerHoneyPot/localTesting
tar -czf bot_data_backup_$(date +%Y%m%d).tar.gz data/bot_data.db
```

### 2. Deploy New Code

```bash
# Pull latest from GitHub
cd ~/crawlerHoneyPot
git pull

# Rebuild containers
cd localTesting
docker-compose down
docker-compose up -d --build
```

### 3. Verify Migration

```bash
# Check parser logs
docker-compose logs parser | tail -20

# Should see:
# ✓ Database initialized with enhanced schema
# ✓ Signatures loaded

# Check database schema
docker-compose exec dashboard sqlite3 /data/bot_data.db "PRAGMA table_info(bot_traffic);"

# Should include: threat_level and threat_score columns
```

### 4. Monitor New Classifications

```bash
# Watch live traffic
docker-compose logs -f parser

# You should see output like:
# 🟢 [benign] benign_search_engines | / | 66.249.64.1
# 🟡 [reconnaissance] recon_vulnerability_scanning | /wp-admin/ | 45.123.45.67
# 🔴 [malicious] malicious_rce_attempts | /shell?wget... | 123.45.67.89
```

## Dashboard Changes

### New Metrics

**Threat Level Cards:**
- Shows count and percentage for each threat level
- Color-coded (green/yellow/red)

**Updated Language:**
- "Total Requests" (not "Total Attacks")
- "Requests Today" (not "Attacks Today")
- "Traffic Categories" (not "Attack Categories")

**New API Endpoints:**
- `/api/threat-distribution` - Threat level breakdown with percentages
- `/api/malicious-activity` - Details on malicious traffic only

## Querying the Enhanced Data

### Useful SQL Queries

```sql
-- Threat level distribution
SELECT threat_level, COUNT(*), 
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM bot_traffic), 1) as percentage
FROM bot_traffic 
GROUP BY threat_level;

-- Most dangerous sources (by threat score)
SELECT ip, SUM(threat_score) as total_threat, COUNT(*) as requests
FROM bot_traffic
GROUP BY ip
ORDER BY total_threat DESC
LIMIT 10;

-- Benign vs malicious traffic over time
SELECT DATE(timestamp) as date, threat_level, COUNT(*)
FROM bot_traffic
WHERE timestamp > date('now', '-7 days')
GROUP BY date, threat_level
ORDER BY date, threat_level;

-- Most common malicious patterns
SELECT category, COUNT(*) as count
FROM bot_traffic
WHERE threat_level = 'malicious'
GROUP BY category
ORDER BY count DESC;

-- Reconnaissance that escalated to malicious
SELECT ip, 
       SUM(CASE WHEN threat_level='reconnaissance' THEN 1 ELSE 0 END) as recon_count,
       SUM(CASE WHEN threat_level='malicious' THEN 1 ELSE 0 END) as malicious_count
FROM bot_traffic
GROUP BY ip
HAVING recon_count > 0 AND malicious_count > 0
ORDER BY malicious_count DESC;
```

## Understanding the Scoring

### How Scores Are Calculated

```python
Base Score = User-Agent Score + Path Score

Examples:
- Googlebot + /robots.txt = -10 + 0 = -10 (Benign)
- curl + /.env = 5 + 15 = 20 (Malicious)
- python-requests + /wp-admin/ = 5 + 10 = 15 (Reconnaissance)
- Unknown user + /shell?wget = 0 + 50 = 50 (Malicious)
```

### Score Ranges

- **< 0**: Definitely benign (legitimate bots)
- **0-4**: Probably benign
- **5-9**: Low suspicion
- **10-19**: Reconnaissance
- **20-39**: High threat
- **40+**: Critical threat

## Benefits for Your LinkedIn Post

The new classification lets you say:

**Before:**
"15,874 attacks from 1,851 IPs"

**After:**
"15,874 requests analyzed:
- 27% benign (legitimate bots)
- 60% reconnaissance (vulnerability scanning)
- 13% malicious (active exploitation attempts)

Shows the difference between curious scanners and actual threats."

Much more nuanced and professional!

## Troubleshooting

### Database Migration Failed

```bash
# Manual migration if automatic fails
docker-compose exec dashboard sqlite3 /data/bot_data.db

# In SQLite:
ALTER TABLE bot_traffic ADD COLUMN threat_level TEXT DEFAULT 'unknown';
ALTER TABLE bot_traffic ADD COLUMN threat_score INTEGER DEFAULT 0;
.quit
```

### Old Data Shows as "Unknown"

This is expected. Run the parser for a few hours to get new classified data, or:

```bash
# Re-classify existing data (advanced)
python3 reclassify_old_data.py  # Would need to create this script
```

### Dashboard Not Showing Threat Cards

Check browser console for errors. Make sure:
- API endpoint returns data: `curl http://localhost:8080/api/threat-distribution`
- JavaScript is loading: View source, check for dashboard.js
- CSS is loading: Check for threat-grid styles

## Next Steps

1. Test locally first
2. Deploy to production
3. Monitor for 24 hours
4. Check threat distribution makes sense
5. Use new data for LinkedIn post
6. Show off the nuanced understanding!

## Reverting (If Needed)

```bash
# Restore old code
git checkout HEAD~1 parser/bot_parser.py
git checkout HEAD~1 parser/bot_signatures.json
git checkout HEAD~1 dashboard/

# Rebuild
docker-compose down
docker-compose up -d --build
```

Your old database will still work with the old code (threat_level/threat_score columns will just be ignored).

