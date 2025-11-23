# Local Bot Traffic Honeypot

Minimal Docker-based honeypot for testing bot monitoring tools locally.

## Quick Start

1. Start honeypot:
```bash
docker-compose up --build
```

2. Test with curl (in another terminal):
```bash
# Test different bot types
curl -A "Googlebot/2.1" http://localhost:8080/wp-admin/
curl -A "AhrefsBot/7.0" http://localhost:8080/admin
curl -A "Nikto/2.1.6" http://localhost:8080/.env
curl -A "python-requests/2.28.0" http://localhost:8080/
```

3. View collected data:
```bash
sqlite3 data/bot_data.db "SELECT * FROM bot_traffic ORDER BY id DESC LIMIT 10;"
```

## What It Does

- Serves fake WordPress/admin bait pages via nginx on localhost:8080
- Python parser monitors logs in real-time
- Classifies bots: search engines, SEO crawlers, security scanners, scrapers
- Stores all traffic data in SQLite database

## Structure

```
nginx/          - Web server config and bait HTML
parser/         - Python bot classifier with ngrok
logs/           - nginx access logs (shared volume)
data/           - SQLite database output
```

## Testing Locally

```bash
# Test with curl
curl http://localhost:8080/wp-admin/

# View live logs
docker-compose logs -f parser
```

