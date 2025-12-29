# Bot Honeypot - Command Reference

## Quick Start

# Start honeypot
docker-compose up -d --build

# Stop honeypot
docker-compose down

# Restart after config changes
docker-compose restart## Docker Commands

### Container Management
# View running containers
docker ps

# View all containers (including stopped)
docker ps -a

# Stop all containers
docker-compose down

# Restart specific service
docker-compose restart parser
docker-compose restart nginx

# Rebuild after code changes
docker-compose up -d --build### Logs & Monitoring
# View parser logs (live tail)
docker-compose logs -f parser

# View nginx logs (live tail)
docker-compose logs -f nginx

# View all logs
docker-compose logs -f

# View last 50 lines
docker-compose logs --tail=50 parser### Exec Into Containers
# Shell into parser container
docker exec -it localtesting_parser_1 /bin/sh

# Shell into nginx container
docker exec -it localtesting_nginx_1 /bin/sh

# Run one-off command
docker exec localtesting_nginx_1 cat /var/log/nginx/access.log### Cleanup
# Remove stopped containers
docker-compose rm

# Remove all unused images
docker image prune -a

# Full cleanup (containers, networks, images)
docker system prune -a

# Clear logs and database
rm logs/access.log logs/error.log
rm data/bot_data.db## Database Queries

### View Bot Traffic
# All traffic
sqlite3 data/bot_data.db "SELECT * FROM bot_traffic;"

# Recent 10 entries
sqlite3 data/bot_data.db "SELECT * FROM bot_traffic ORDER BY id DESC LIMIT 10;"

# Count by category
sqlite3 data/bot_data.db "SELECT category, COUNT(*) as count FROM bot_traffic GROUP BY category ORDER BY count DESC;"

# Show specific category
sqlite3 data/bot_data.db "SELECT * FROM bot_traffic WHERE category='security_scanner';"

# Top paths hit
sqlite3 data/bot_data.db "SELECT path, COUNT(*) as hits FROM bot_traffic GROUP BY path ORDER BY hits DESC;"

# Unique IPs
sqlite3 data/bot_data.db "SELECT COUNT(DISTINCT ip) as unique_ips FROM bot_traffic;"### Interactive SQLite
# Open database shell
sqlite3 data/bot_data.db

# Inside sqlite:
.tables                    # Show tables
.schema bot_traffic        # Show table structure
SELECT * FROM bot_traffic LIMIT 5;
.quit                      # Exit## System Admin Commands

### Server Management
# Check disk space
df -h

# Check memory usage
free -h

# Check CPU usage
top
# (press 'q' to quit)

# Check network connections
netstat -tuln | grep LISTEN

# Check which process uses port 80
lsof -i :80### Firewall (UFW)
# Check firewall status
ufw status

# Check verbose
ufw status verbose

# Allow new port
ufw allow 443/tcp

# Deny port
ufw deny 8080/tcp

# Delete rule by number
ufw status numbered
ufw delete [number]

# Disable/enable firewall
ufw disable
ufw enable### File Management
# Find large files
du -h --max-depth=1 | sort -hr

# Check log file size
ls -lh logs/

# Tail access log
tail -f logs/access.log

# Count lines in log
wc -l logs/access.log

# Search logs for pattern
grep "Googlebot" logs/access.log### Update System
# Update packages
apt update && apt upgrade -y

# Update Docker images
docker-compose pull
docker-compose up -d

# Restart server
reboot## Testing

### Test from localhost
curl http://localhost/
curl -A "Googlebot/2.1" http://localhost/wp-admin/
curl -A "AhrefsBot/7.0" http://localhost/admin### Test from external (Mac)
# Replace with your IP/domain
curl http://YOUR_IP/
curl -A "Nikto/2.1.6" http://YOUR_IP/.env
curl http://yourdomain.duckdns.org/### Load Testing
# Send 100 requests
for i in {1..100}; do curl -A "TestBot/1.0" http://localhost/; done

# Check parser caught them
docker-compose logs parser | tail -20## Troubleshooting

### Container won't start
# Check logs
docker-compose logs

# Check if port already in use
lsof -i :80

# Remove and rebuild
docker-compose down
docker-compose up --build### No bot traffic detected
# Check nginx is accessible
curl -v http://localhost/

# Check log file exists
ls -la logs/

# Check parser is running
docker-compose logs parser

# Manually check nginx logs
docker exec localtesting_nginx_1 cat /var/log/nginx/access.log### Database locked
# Stop parser
docker-compose stop parser

# Query database
sqlite3 data/bot_data.db "SELECT COUNT(*) FROM bot_traffic;"

# Restart
docker-compose start parser### Out of disk space
# Check usage
df -h

# Clean Docker
docker system prune -a

# Rotate/compress old logs
gzip logs/access.log.old## Auto-Start on Boot

# Install Docker to start on boot
systemctl enable docker

# Make containers auto-restart
# Add to docker-compose.yml under each service:
#   restart: unless-stopped## Daily Monitoring Script

Create `~/check_honeypot.sh`:
#!/bin/bash
echo "=== Honeypot Status ==="
docker ps
echo ""
echo "=== Bot Count by Category ==="
sqlite3 ~/crawlerHoneyPot/localTesting/data/bot_data.db \
  "SELECT category, COUNT(*) FROM bot_traffic GROUP BY category;"
echo ""
echo "=== Last 5 Hits ==="
sqlite3 ~/crawlerHoneyPot/localTesting/data/bot_data.db \
  "SELECT timestamp, category, path FROM bot_traffic ORDER BY id DESC LIMIT 5;"Make executable:
chmod +x ~/check_honeypot.sh
./check_honeypot.sh## DuckDNS Auto-Update

# Update DuckDNS IP (if needed)
echo url="https://www.duckdns.org/update?domains=YOURDOMAIN&token=YOUR_TOKEN&ip=" | curl -k -o ~/duckdns.log -K -

# Setup cron for auto-update
crontab -e
# Add: */5 * * * * ~/duckdns.sh >/dev/null 2>&1


 grep CRON /var/log/syslog | tail -20


 