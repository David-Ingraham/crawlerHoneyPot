# Local Testing Guide

Quick guide for testing the complete honeypot + dashboard system on your Mac.

## Prerequisites

- Docker Desktop installed and running
- Terminal access
- Git (for syncing to Linode later)

## Quick Start

### 1. Verify Database Exists

```bash
cd /Users/davidingraham/Desktop/personal_projects/cyberSec/crawlerTrafficBait/localTesting

# Check if database file exists
ls -lh data/bot_data.db

# Check database contents
sqlite3 data/bot_data.db "SELECT COUNT(*) FROM bot_traffic;"
```

If no database exists, you can copy from Linode:

```bash
# On Linode
cd ~/crawlerHoneyPot/localTesting
tar -czf bot_data.tar.gz data/bot_data.db

# On your Mac
scp root@your-linode-ip:~/crawlerHoneyPot/localTesting/bot_data.tar.gz .
tar -xzf bot_data.tar.gz
```

### 2. Build and Run Everything

```bash
# Build all containers
docker-compose build

# Start all services
docker-compose up

# Or run in background:
docker-compose up -d
```

### 3. Access Services

**Honeypot:** http://localhost (port 80)
- Try: http://localhost/wp-admin/
- Try: http://localhost/.env
- Try: http://localhost/admin/

**Dashboard:** http://localhost:8080
- Main dashboard with charts
- About page: http://localhost:8080/about

### 4. Generate Test Traffic

Open another terminal and generate fake attacks:

```bash
# Test various paths
curl http://localhost/wp-admin/
curl http://localhost/.env
curl http://localhost/.git/config
curl -A "Googlebot/2.1" http://localhost/
curl -A "Nikto/2.1.6" http://localhost/admin/
curl -A "python-requests/2.28.0" http://localhost/.env

# Generate multiple requests
for i in {1..20}; do
  curl http://localhost/wp-admin/
  curl http://localhost/.env
  sleep 1
done
```

Wait 30 seconds, then refresh dashboard to see new data.

### 5. Check Logs

```bash
# View all container logs
docker-compose logs

# Follow logs in real-time
docker-compose logs -f

# View specific service
docker-compose logs nginx
docker-compose logs parser
docker-compose logs dashboard

# Check bot parser output
docker-compose logs -f parser
```

### 6. Query Database Directly

```bash
# Total entries
sqlite3 data/bot_data.db "SELECT COUNT(*) FROM bot_traffic;"

# Recent entries
sqlite3 data/bot_data.db "SELECT timestamp, ip, path FROM bot_traffic ORDER BY id DESC LIMIT 10;"

# Category breakdown
sqlite3 data/bot_data.db "SELECT category, COUNT(*) FROM bot_traffic GROUP BY category;"

# Top IPs
sqlite3 data/bot_data.db "SELECT ip, COUNT(*) as count FROM bot_traffic GROUP BY ip ORDER BY count DESC LIMIT 10;"
```

## Verify Each Component

### Check Nginx

```bash
# Should return your honeypot homepage
curl http://localhost/

# Should return fake WordPress response
curl http://localhost/wp-admin/

# Should return fake env file
curl http://localhost/.env
```

### Check Parser

```bash
# Should show bot classification messages
docker-compose logs parser | tail -20
```

### Check Dashboard API

```bash
# Get statistics
curl http://localhost:8080/api/stats | python3 -m json.tool

# Get top IPs
curl http://localhost:8080/api/top-ips | python3 -m json.tool

# Get recent attacks
curl http://localhost:8080/api/recent | python3 -m json.tool
```

### Check Dashboard UI

Open in browser:
1. http://localhost:8080 - Should show charts with data
2. Click around, verify charts load
3. Check responsive design (resize browser)
4. Verify auto-refresh works (watch for 30 seconds)

## Common Issues

### Port Already in Use

```bash
# Check what's using port 80
sudo lsof -i :80

# Check port 8080
lsof -i :8080

# Kill process if needed
kill -9 <PID>
```

### Database Not Found

```bash
# Check file exists
ls -la data/

# Create empty database if needed (parser will initialize)
touch data/bot_data.db
```

### Docker Build Fails

```bash
# Clean rebuild
docker-compose down
docker-compose build --no-cache
docker-compose up
```

### No Data in Dashboard

1. Verify database has entries
2. Check dashboard logs for errors
3. Verify volume mounts in docker-compose.yml
4. Try generating test traffic (see section 4)

## Stop Services

```bash
# Stop all containers
docker-compose down

# Stop and remove volumes (careful!)
docker-compose down -v

# Stop but keep containers
docker-compose stop
```

## Edit and Reload

### After editing dashboard code:

```bash
# Rebuild and restart dashboard only
docker-compose up -d --build dashboard
```

### After editing nginx config:

```bash
# Restart nginx only
docker-compose restart nginx
```

### After editing parser:

```bash
# Rebuild and restart parser
docker-compose up -d --build parser
```

## Testing Checklist

- [ ] All containers start without errors
- [ ] Honeypot responds on port 80
- [ ] Dashboard loads on port 8080
- [ ] Charts display with data
- [ ] Recent attacks table populates
- [ ] Auto-refresh works (wait 30s)
- [ ] About page loads
- [ ] Test traffic appears in dashboard
- [ ] Parser logs show classifications
- [ ] Database grows with new requests

## Performance Check

```bash
# Check container resource usage
docker stats

# Check database size
du -h data/bot_data.db

# Check log file sizes
du -h logs/
```

## Sync to Linode

Once everything works locally:

```bash
# Commit changes
git add .
git commit -m "Add dashboard feature"

# Push to repo (if using git)
git push

# On Linode, pull changes
ssh root@your-linode-ip
cd ~/crawlerHoneyPot
git pull
docker-compose down
docker-compose up -d --build
```

Or use rsync:

```bash
# From your Mac
rsync -avz --exclude 'data/' --exclude 'logs/' \
  localTesting/ root@your-linode-ip:~/crawlerHoneyPot/localTesting/
```

## Next Steps

After local testing passes:
1. Buy domain name
2. Configure DNS to point to Linode IP
3. Update nginx.conf with domain names
4. Deploy to Linode
5. Test from external network
6. Create LinkedIn post


