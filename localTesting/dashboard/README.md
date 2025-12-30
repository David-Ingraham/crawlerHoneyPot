# Honeypot Dashboard

Real-time visualization dashboard for honeypot traffic analysis.

## Features

- Live statistics (total attacks, unique IPs, today's count)
- Interactive charts using Chart.js
- Attack categorization (search engines, scanners, bots)
- Top attacking IPs and most targeted paths
- Timeline visualization
- Recent attacks table with real-time updates
- About page explaining the project
- Responsive design (mobile-friendly)
- Auto-refresh every 30 seconds

## Technology Stack

- **Backend:** Flask (Python 3.11)
- **Database:** SQLite
- **Frontend:** HTML5, CSS3, JavaScript
- **Charts:** Chart.js
- **Container:** Docker

## Local Testing

### Option 1: Docker (Recommended)

```bash
# From localTesting directory
docker-compose up --build

# Access dashboard at:
# http://localhost:8080
```

### Option 2: Direct Python

```bash
cd dashboard

# Install dependencies
pip install -r requirements.txt

# Set database path
export DB_PATH=../data/bot_data.db

# Run Flask app
python app.py

# Access at http://localhost:8080
```

## API Endpoints

- `GET /` - Main dashboard
- `GET /about` - About page
- `GET /api/stats` - Overall statistics
- `GET /api/top-ips` - Top 10 attacking IPs
- `GET /api/top-paths` - Most targeted paths
- `GET /api/timeline` - Attack timeline (last 7 days)
- `GET /api/recent` - 20 most recent attacks
- `GET /api/attack-types` - Attack classification by path patterns

## Customization

### Update Colors

Edit `static/style.css` and modify CSS variables:

```css
:root {
    --primary-color: #2563eb;
    --secondary-color: #1e40af;
    /* ... */
}
```

### Add New Charts

1. Add chart canvas to `templates/index.html`
2. Create API endpoint in `app.py`
3. Initialize and update chart in `static/dashboard.js`

### Change Refresh Rate

In `static/dashboard.js`, modify:

```javascript
// Refresh every 30 seconds (30000ms)
setInterval(loadAllData, 30000);
```

## Production Deployment

### Environment Variables

- `DB_PATH` - Path to SQLite database (default: `/data/bot_data.db`)
- `PORT` - Port to run on (default: `8080`)

### Docker Compose

The dashboard is already configured in `../docker-compose.yml`:

```yaml
dashboard:
  build: ./dashboard
  ports:
    - "8080:8080"
  volumes:
    - ./data:/data:ro  # Read-only access to database
```

### With Nginx Reverse Proxy

To serve on port 80 via domain name, add to nginx.conf:

```nginx
server {
    listen 80;
    server_name dashboard.yourdomain.com;
    
    location / {
        proxy_pass http://dashboard:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Security Notes

- Database is mounted read-only (`:ro`) - dashboard cannot modify data
- No authentication by default - add if exposing publicly with sensitive data
- CORS not configured - add if building separate frontend
- Rate limiting not implemented - consider adding for public deployment

## Troubleshooting

### Database not found

Check that `bot_data.db` exists in the `data/` directory:

```bash
ls -lh ../data/bot_data.db
```

### No data showing

Verify the database has data:

```bash
sqlite3 ../data/bot_data.db "SELECT COUNT(*) FROM bot_traffic;"
```

### Port already in use

Change port in docker-compose.yml or use different port:

```bash
PORT=8081 python app.py
```

## Future Enhancements

- [ ] Add authentication (basic auth or OAuth)
- [ ] Export data to CSV/JSON
- [ ] Geolocation map of attackers
- [ ] Email/Slack notifications for interesting attacks
- [ ] Historical comparison (week over week)
- [ ] Custom date range filtering
- [ ] Attack signature search
- [ ] Dark/light mode toggle


