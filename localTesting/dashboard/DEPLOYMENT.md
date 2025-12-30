# Dashboard Deployment Guide

## Step 1: Domain Purchase (Recommended Vendors)

### Top Picks:
1. **Porkbun** (Best value)
   - https://porkbun.com
   - .com: $9.13/year
   - Free WHOIS privacy
   - No upsells

2. **Cloudflare Registrar** (Cheapest)
   - https://www.cloudflare.com/products/registrar/
   - .com: $9.77/year (at-cost)
   - Includes CDN/DNS
   - Need Cloudflare account

3. **Namecheap** (Popular)
   - https://www.namecheap.com
   - .com: $13.98/year (first year)
   - Free WHOIS privacy

### Suggested Domain Names:
- `yourname-security.com`
- `threat-research.io`
- `honeypot-analytics.com`
- `cybersec-lab.com`
- `infosec-project.com`

## Step 2: Configure DNS

After purchasing domain, add these DNS records:

```
Type: A
Name: @
Value: YOUR_LINODE_IP
TTL: 3600

Type: A  
Name: dashboard
Value: YOUR_LINODE_IP
TTL: 3600

Type: A
Name: honeypot
Value: YOUR_LINODE_IP
TTL: 3600
```

This creates:
- `yourdomain.com` → Your Linode
- `dashboard.yourdomain.com` → Dashboard
- `honeypot.yourdomain.com` → Honeypot

## Step 3: Test Locally First

```bash
cd /Users/davidingraham/Desktop/personal_projects/cyberSec/crawlerTrafficBait/localTesting

# Build and start everything
docker-compose up --build

# Test:
# - Honeypot: http://localhost
# - Dashboard: http://localhost:8080
```

See [TESTING.md](../TESTING.md) for detailed testing guide.

## Step 4: Get Real Data from Linode

Your local database only has 3 test entries. Get the real data:

```bash
# On Linode:
cd ~/crawlerHoneyPot/localTesting
tar -czf bot_data_backup.tar.gz data/bot_data.db

# On your Mac:
scp root@YOUR_LINODE_IP:~/crawlerHoneyPot/localTesting/bot_data_backup.tar.gz .
tar -xzf bot_data_backup.tar.gz

# Now you have the real 15,671+ entries locally for testing
```

## Step 5: Push to Linode

### Option A: Via Git (Recommended)

```bash
# Initialize git repo if not already done
cd /Users/davidingraham/Desktop/personal_projects/cyberSec/crawlerTrafficBait
git init
git add .
git commit -m "Add dashboard feature"

# Push to your remote (GitHub, GitLab, etc.)
git push origin main

# On Linode:
cd ~/crawlerHoneyPot
git pull
docker-compose down
docker-compose up -d --build
```

### Option B: Via rsync

```bash
# From your Mac
rsync -avz --exclude 'data/' --exclude 'logs/' \
  /Users/davidingraham/Desktop/personal_projects/cyberSec/crawlerTrafficBait/localTesting/ \
  root@YOUR_LINODE_IP:~/crawlerHoneyPot/localTesting/

# On Linode:
cd ~/crawlerHoneyPot/localTesting
docker-compose down
docker-compose up -d --build
```

## Step 6: Configure Domain Routing (Optional - For Port 80)

If you want both services on port 80 with different domains, update nginx.conf:

```nginx
# Add this server block for dashboard
server {
    listen 80;
    server_name dashboard.yourdomain.com;
    
    location / {
        proxy_pass http://dashboard:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

# Update honeypot server block
server {
    listen 80;
    server_name honeypot.yourdomain.com;
    
    # ... existing honeypot config ...
}
```

Then update docker-compose.yml to NOT expose dashboard port externally:

```yaml
dashboard:
  build: ./dashboard
  # Remove: ports: - "8080:8080"
  expose:
    - "8080"  # Only internal access
  volumes:
    - ./data:/data:ro
  environment:
    - DB_PATH=/data/bot_data.db
  networks:
    - honeypot
```

## Step 7: Verify Deployment

```bash
# Check all containers running
docker-compose ps

# Should see:
# - nginx (port 80)
# - parser (no exposed ports)
# - dashboard (port 8080 or internal only)

# Test from external network (your phone, different computer):
curl http://dashboard.yourdomain.com:8080
# or if using nginx proxy:
curl http://dashboard.yourdomain.com
```

## Step 8: LinkedIn Post

Once everything is working, create your LinkedIn post:

### Post Template:

```
I've been running an internet honeypot for the past 2 months to study 
real-world attack patterns targeting web servers.

Results so far:
• 15,671 attacks logged
• 1,851 unique IP addresses
• [X] countries represented
• Most common: PHPUnit RCE attempts, credential harvesting, botnet recruitment

Check out the live dashboard: https://dashboard.yourdomain.com

The honeypot itself is running at: https://honeypot.yourdomain.com
(Yes, you can visit it - but there's nothing to exploit!)

Tech stack: Docker, Nginx, Python, Flask, SQLite, Chart.js

Key insights:
🔍 40% of attacks are automated vulnerability scanners
🔐 30% are hunting for .env files and credentials  
🤖 20% are botnet recruitment attempts
📊 Most bots don't care if you label it as a honeypot

The honeypot is completely passive - it just logs requests and returns 
fake responses. No real vulnerabilities exist.

Open to discussing security research, honeypot design, or threat intelligence!

#cybersecurity #infosec #honeypot #threatintelligence #python #docker
```

## Architecture Overview

```
Internet Traffic
    ↓
Linode IP (YOUR_LINODE_IP)
    ↓
┌─────────────────────────────────────┐
│  Docker Host                         │
│                                      │
│  Port 80: Nginx                     │
│    ├─ honeypot.yourdomain.com      │
│    │   └─ Serves fake vulnerable   │
│    │      pages, logs everything    │
│    │                                │
│    └─ dashboard.yourdomain.com      │
│        └─ Proxies to dashboard:8080│
│                                      │
│  Parser Container                   │
│    └─ Reads logs, builds SQLite DB │
│                                      │
│  Dashboard Container (8080)         │
│    └─ Flask app, reads SQLite DB   │
│                                      │
│  Shared Volumes:                    │
│    ├─ ./logs (nginx → parser)      │
│    └─ ./data (parser → dashboard)  │
└─────────────────────────────────────┘
```

## Monitoring & Maintenance

### Check System Health

```bash
# Container status
docker-compose ps

# Resource usage
docker stats

# Logs
docker-compose logs -f dashboard
docker-compose logs -f parser

# Database size
du -h data/bot_data.db

# Disk space
df -h
```

### Database Backup

```bash
# Automated daily backup (add to cron)
0 2 * * * cd ~/crawlerHoneyPot/localTesting && tar -czf backups/bot_data_$(date +\%Y\%m\%d).tar.gz data/bot_data.db
```

### Log Rotation

Nginx logs will grow indefinitely. Set up rotation:

```bash
# /etc/logrotate.d/honeypot
/root/crawlerHoneyPot/localTesting/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 0644 root root
}
```

## Troubleshooting

### Dashboard shows no data
- Check database file exists and has data
- Verify volume mounts in docker-compose.yml
- Check dashboard logs: `docker-compose logs dashboard`

### Can't access externally
- Check Linode firewall allows ports 80 and 8080
- Verify DNS propagation: `dig yourdomain.com`
- Test from external network, not localhost

### Containers keep restarting
- Check logs: `docker-compose logs`
- Verify all files copied correctly
- Check disk space: `df -h`

### Updates not appearing
- Force rebuild: `docker-compose up -d --build --force-recreate`
- Clear browser cache
- Check you're editing correct files

## Security Checklist

- [ ] HTTPS/SSL not yet implemented (future enhancement)
- [ ] No authentication on dashboard (fine if public)
- [ ] Database mounted read-only in dashboard
- [ ] Honeypot has no real vulnerabilities
- [ ] SSH key authentication enabled (disable passwords)
- [ ] Firewall configured (UFW or Linode firewall)
- [ ] Regular backups automated
- [ ] Monitoring alerts set up (optional)

## Cost Estimate

- Linode Nanode 1GB: $5/month
- Domain: $9-13/year ($1/month)
- **Total: ~$6/month**

## Next Enhancements

- [ ] Add HTTPS with Let's Encrypt
- [ ] Geolocation map of attackers
- [ ] Export data to CSV
- [ ] Email alerts for interesting attacks
- [ ] API key for restricted access
- [ ] Dark mode toggle
- [ ] Historical date range filtering


