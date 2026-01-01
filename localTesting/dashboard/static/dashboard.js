// Dashboard JavaScript
// Handles real-time data updates and chart rendering

// Chart instances
let categoriesChart, attackTypesChart, topIpsChart, topPathsChart, timelineChart, attackMap;

// Data mappings for chart clicks
let categoryDataMap = [];
let ipDataMap = [];
let pathDataMap = [];
let patternDataMap = {};

// Chart colors
const chartColors = {
    primary: 'rgba(37, 99, 235, 0.8)',
    secondary: 'rgba(59, 130, 246, 0.8)',
    success: 'rgba(16, 185, 129, 0.8)',
    danger: 'rgba(239, 68, 68, 0.8)',
    warning: 'rgba(245, 158, 11, 0.8)',
    info: 'rgba(99, 102, 241, 0.8)',
};

const colorPalette = [
    'rgba(37, 99, 235, 0.8)',
    'rgba(16, 185, 129, 0.8)',
    'rgba(239, 68, 68, 0.8)',
    'rgba(245, 158, 11, 0.8)',
    'rgba(99, 102, 241, 0.8)',
    'rgba(236, 72, 153, 0.8)',
    'rgba(14, 165, 233, 0.8)',
    'rgba(168, 85, 247, 0.8)',
];

// Chart.js default config
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = '#334155';

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    initializeMap();
    loadInitialData();
    
    // Refresh data every 30 seconds (without reloading map)
    setInterval(loadAllData, 30000);
});

// Initialize all charts
function initializeCharts() {
    // Categories pie chart
    const ctxCategories = document.getElementById('categoriesChart').getContext('2d');
    categoriesChart = new Chart(ctxCategories, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: colorPalette,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'right',
                    align: 'center',
                    labels: {
                        boxWidth: 15,
                        padding: 10,
                        font: {
                            size: 11
                        }
                    }
                }
            },
            onClick: (event, elements) => {
                if (elements.length > 0) {
                    const index = elements[0].index;
                    const categoryName = categoriesChart.data.labels[index];
                    const originalCategory = categoryDataMap[index];
                    openRequestModal('category', originalCategory, `${categoryName} Requests`);
                }
            }
        }
    });

    // Attack types bar chart
    const ctxAttackTypes = document.getElementById('attackTypesChart').getContext('2d');
    attackTypesChart = new Chart(ctxAttackTypes, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Attacks',
                data: [],
                backgroundColor: chartColors.primary,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            onClick: (event, elements) => {
                if (elements.length > 0) {
                    const index = elements[0].index;
                    const attackType = attackTypesChart.data.labels[index];
                    const pattern = patternDataMap[attackType];
                    if (pattern) {
                        openRequestModal('pattern', pattern, `${attackType} Requests`);
                    }
                }
            }
        }
    });

    // Top IPs horizontal bar chart
    const ctxTopIps = document.getElementById('topIpsChart').getContext('2d');
    topIpsChart = new Chart(ctxTopIps, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Requests',
                data: [],
                backgroundColor: chartColors.danger,
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true
                }
            },
            onClick: (event, elements) => {
                if (elements.length > 0) {
                    const index = elements[0].index;
                    const ip = ipDataMap[index];
                    if (ip) {
                        openRequestModal('ip', ip, `Requests from ${ip}`);
                    }
                }
            }
        }
    });

    // Top paths horizontal bar chart
    const ctxTopPaths = document.getElementById('topPathsChart').getContext('2d');
    topPathsChart = new Chart(ctxTopPaths, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Hits',
                data: [],
                backgroundColor: chartColors.warning,
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true
                }
            },
            onClick: (event, elements) => {
                if (elements.length > 0) {
                    const index = elements[0].index;
                    const path = pathDataMap[index];
                    if (path) {
                        openRequestModal('path', path, `Requests to ${path}`);
                    }
                }
            }
        }
    });

    // Timeline line chart
    const ctxTimeline = document.getElementById('timelineChart').getContext('2d');
    timelineChart = new Chart(ctxTimeline, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Attacks per Hour',
                data: [],
                borderColor: chartColors.primary,
                backgroundColor: 'rgba(37, 99, 235, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Load initial data (includes map)
async function loadInitialData() {
    try {
        await loadAllData();
        await loadGeoLocations();
    } catch (error) {
        console.error('Error loading initial data:', error);
    }
}

// Load all data (for periodic refresh, excludes map)
async function loadAllData() {
    try {
        await Promise.all([
            loadStats(),
            loadThreatDistribution(),
            loadTopIps(),
            loadTopPaths(),
            loadTimeline(),
            loadAttackTypes(),
            loadRecent()
        ]);
    } catch (error) {
        console.error('Error loading data:', error);
    }
}

// Load statistics
async function loadStats() {
    const response = await fetch('/api/stats');
    const data = await response.json();
    
    document.getElementById('total-requests').textContent = formatNumber(data.total_requests);
    document.getElementById('unique-ips').textContent = formatNumber(data.unique_ips);
    document.getElementById('today-count').textContent = formatNumber(data.today);
    
    // Update categories chart (top 10 categories)
    if (data.categories && data.categories.length > 0) {
        // Store original category names for click handling
        categoryDataMap = data.categories.map(c => c.name);
        
        updateChart(categoriesChart, 
            data.categories.map(c => formatCategoryName(c.name)),
            data.categories.map(c => c.count)
        );
    }
}

// Load threat distribution
async function loadThreatDistribution() {
    const response = await fetch('/api/threat-distribution');
    const data = await response.json();
    
    // Update threat level cards
    data.forEach(item => {
        const level = item.threat_level;
        const countElem = document.getElementById(`${level}-count`);
        const percentElem = document.getElementById(`${level}-percent`);
        
        if (countElem) {
            countElem.textContent = formatNumber(item.count);
        }
        if (percentElem) {
            percentElem.textContent = `${item.percentage}%`;
        }
    });
}

// Load top IPs
async function loadTopIps() {
    const response = await fetch('/api/top-ips');
    const data = await response.json();
    
    // Store IPs for click handling
    ipDataMap = data.map(item => item.ip);
    
    updateChart(topIpsChart,
        data.map(item => item.ip),
        data.map(item => item.count)
    );
}

// Load top paths
async function loadTopPaths() {
    const response = await fetch('/api/top-paths');
    const data = await response.json();
    
    // Store full paths for click handling
    pathDataMap = data.map(item => item.path);
    
    // Truncate long paths for display
    const labels = data.map(item => 
        item.path.length > 40 ? item.path.substring(0, 40) + '...' : item.path
    );
    
    updateChart(topPathsChart,
        labels,
        data.map(item => item.count)
    );
}

// Load timeline
async function loadTimeline() {
    const response = await fetch('/api/timeline');
    const data = await response.json();
    
    // Format timestamps for display
    const labels = data.map(item => {
        const parts = item.time.split(':');
        return `${parts[0]}:${parts[1]}`;
    });
    
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = data.map(item => item.count);
    timelineChart.update();
}

// Load attack types
async function loadAttackTypes() {
    const response = await fetch('/api/attack-types');
    const data = await response.json();
    
    // Store pattern mapping for click handling
    patternDataMap = {};
    data.forEach(item => {
        patternDataMap[item.type] = item.pattern;
    });
    
    updateChart(attackTypesChart,
        data.map(item => item.type),
        data.map(item => item.count)
    );
}

// Load recent attacks
async function loadRecent() {
    const response = await fetch('/api/recent');
    const data = await response.json();
    
    const tbody = document.querySelector('#recent-attacks tbody');
    tbody.innerHTML = '';
    
    data.forEach(attack => {
        const row = tbody.insertRow();
        row.innerHTML = `
            <td>${attack.timestamp}</td>
            <td><code>${attack.ip}</code></td>
            <td><code>${escapeHtml(attack.path)}</code></td>
            <td class="user-agent">${escapeHtml(attack.user_agent)}</td>
            <td><span class="badge">${attack.category}</span></td>
        `;
    });
}

// Update chart helper
function updateChart(chart, labels, data) {
    chart.data.labels = labels;
    chart.data.datasets[0].data = data;
    chart.update();
}

// Format number with commas
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Format category names for display
function formatCategoryName(name) {
    return name
        .replace('benign_', '')
        .replace('malicious_', '')
        .replace('recon_', '')
        .replace('scanner_', '')
        .replace('generic_', '')
        .replace(/_/g, ' ')
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}

// Modal functionality
const modal = document.getElementById('threat-modal');
const modalOverlay = modal.querySelector('.modal-overlay');
const modalClose = modal.querySelector('.modal-close');
const modalTitle = document.getElementById('modal-title');
const modalLoading = document.getElementById('modal-loading');
const modalRequests = document.getElementById('modal-requests');

// Add click handlers to threat cards
document.addEventListener('DOMContentLoaded', function() {
    const threatCards = document.querySelectorAll('.threat-card');
    threatCards.forEach(card => {
        card.addEventListener('click', function() {
            const threatLevel = this.classList.contains('benign') ? 'benign' :
                              this.classList.contains('reconnaissance') ? 'reconnaissance' :
                              'malicious';
            const titles = {
                'benign': 'Benign Traffic Analysis',
                'reconnaissance': 'Reconnaissance Traffic Analysis',
                'malicious': 'Malicious Traffic Analysis'
            };
            openRequestModal('threat', threatLevel, titles[threatLevel]);
        });
    });
});

// Generic modal opener for all filter types
function openRequestModal(filterType, filterValue, displayTitle) {
    modalTitle.textContent = displayTitle || 'Request Analysis';
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
    
    // Show loading state
    modalLoading.style.display = 'block';
    modalRequests.style.display = 'none';
    modalRequests.innerHTML = '';
    
    // Fetch data based on filter type
    loadFilteredRequests(filterType, filterValue);
}

// Close modal
function closeModal() {
    modal.classList.remove('active');
    document.body.style.overflow = '';
}

modalClose.addEventListener('click', closeModal);
modalOverlay.addEventListener('click', closeModal);

// Close on escape key
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape' && modal.classList.contains('active')) {
        closeModal();
    }
});

// Load filtered requests (generic for all filter types)
async function loadFilteredRequests(filterType, filterValue) {
    try {
        // Build endpoint URL based on filter type
        let endpoint;
        switch(filterType) {
            case 'threat':
                endpoint = `/api/requests-by-threat/${encodeURIComponent(filterValue)}`;
                break;
            case 'category':
                endpoint = `/api/requests-by-category/${encodeURIComponent(filterValue)}`;
                break;
            case 'ip':
                endpoint = `/api/requests-by-ip/${encodeURIComponent(filterValue)}`;
                break;
            case 'path':
                endpoint = `/api/requests-by-path?path=${encodeURIComponent(filterValue)}`;
                break;
            case 'pattern':
                endpoint = `/api/requests-by-pattern?pattern=${encodeURIComponent(filterValue)}`;
                break;
            default:
                throw new Error('Invalid filter type');
        }
        
        const response = await fetch(endpoint);
        const requests = await response.json();
        
        modalLoading.style.display = 'none';
        modalRequests.style.display = 'block';
        
        if (requests.length === 0) {
            modalRequests.innerHTML = '<div class="modal-loading">No requests found</div>';
            return;
        }
        
        // Update title with count
        const baseTitle = modalTitle.textContent.split(' - ')[0];
        modalTitle.textContent = `${baseTitle} - Showing ${requests.length} requests`;
        
        // Build request cards
        modalRequests.innerHTML = requests.map(req => createRequestCard(req)).join('');
    } catch (error) {
        console.error('Error loading requests:', error);
        modalLoading.style.display = 'none';
        modalRequests.style.display = 'block';
        modalRequests.innerHTML = '<div class="modal-loading">Error loading requests. Please try again.</div>';
    }
}

// Create request card HTML
function createRequestCard(request) {
    const patterns = request.matched_patterns && request.matched_patterns.length > 0
        ? request.matched_patterns.map(p => `<div class="classification-item">${escapeHtml(p)}</div>`).join('')
        : '<div class="classification-item">No specific patterns matched</div>';
    
    const cardId = `card-${Math.random().toString(36).substr(2, 9)}`;
    
    return `
        <div class="request-card" id="${cardId}">
            <div class="request-header">
                <div class="request-meta">
                    <span class="request-time">${escapeHtml(request.timestamp)}</span>
                    <span class="request-ip">${escapeHtml(request.ip)}</span>
                    <button class="ipinfo-btn" onclick="fetchIPInfo('${escapeHtml(request.ip)}', '${cardId}')">ipinfo</button>
                </div>
                <div class="threat-badge ${request.threat_level}">
                    ${request.threat_level} - Score: ${request.threat_score}
                </div>
            </div>
            
            <div class="ipinfo-container" id="${cardId}-ipinfo" style="display: none;"></div>
            
            <div class="request-section">
                <div class="request-label">Request Payload</div>
                <div class="request-value">${escapeHtml(request.path)}</div>
            </div>
            
            <div class="request-section">
                <div class="request-label">User Agent</div>
                <div class="request-value">${escapeHtml(request.user_agent)}</div>
            </div>
            
            <div class="request-section">
                <div class="request-label">Classification Details</div>
                <div class="classification-details">
                    <div class="classification-item">Category: <strong>${escapeHtml(request.category)}</strong></div>
                    <div class="classification-item">Threat Score: <span class="score-display">${request.threat_score}/100</span></div>
                    ${patterns}
                </div>
            </div>
            
            ${request.referer && request.referer !== '-' ? `
            <div class="request-section">
                <div class="request-label">Referer</div>
                <div class="request-value">${escapeHtml(request.referer)}</div>
            </div>
            ` : ''}
            
            <div class="request-section">
                <div class="request-label">Response Status</div>
                <div class="request-value">HTTP ${request.status}</div>
            </div>
        </div>
    `;
}

// Fetch and display IP information
async function fetchIPInfo(ip, cardId) {
    const container = document.getElementById(`${cardId}-ipinfo`);
    const btn = event.target;
    
    // Toggle visibility if already loaded
    if (container.innerHTML && container.style.display === 'block') {
        container.style.display = 'none';
        btn.textContent = 'ipinfo';
        return;
    }
    
    // Show loading state
    btn.textContent = 'loading...';
    btn.disabled = true;
    
    try {
        const response = await fetch(`/api/ipinfo/${ip}`);
        const data = await response.json();
        
        // Build info display
        container.innerHTML = `
            <div class="ipinfo-content">
                <div class="ipinfo-header">IP Information for ${ip}</div>
                <div class="ipinfo-grid">
                    ${data.city ? `<div class="ipinfo-item"><span class="ipinfo-label">Location:</span> ${escapeHtml(data.city)}, ${escapeHtml(data.region)}, ${escapeHtml(data.country)}</div>` : ''}
                    ${data.loc ? `<div class="ipinfo-item"><span class="ipinfo-label">Coordinates:</span> ${escapeHtml(data.loc)}</div>` : ''}
                    ${data.org ? `<div class="ipinfo-item"><span class="ipinfo-label">Organization:</span> ${escapeHtml(data.org)}</div>` : ''}
                    ${data.hostname ? `<div class="ipinfo-item"><span class="ipinfo-label">Hostname:</span> ${escapeHtml(data.hostname)}</div>` : ''}
                    ${data.timezone ? `<div class="ipinfo-item"><span class="ipinfo-label">Timezone:</span> ${escapeHtml(data.timezone)}</div>` : ''}
                    ${data.postal ? `<div class="ipinfo-item"><span class="ipinfo-label">Postal:</span> ${escapeHtml(data.postal)}</div>` : ''}
                </div>
            </div>
        `;
        
        container.style.display = 'block';
        btn.textContent = 'hide';
        btn.disabled = false;
        
    } catch (error) {
        console.error('Error fetching IP info:', error);
        container.innerHTML = `
            <div class="ipinfo-content">
                <div class="ipinfo-error">Failed to fetch IP information. API limit may be reached.</div>
            </div>
        `;
        container.style.display = 'block';
        btn.textContent = 'ipinfo';
        btn.disabled = false;
    }
}

// Initialize attack origins map
function initializeMap() {
    attackMap = L.map('attack-map').setView([20, 0], 2);
    
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        maxZoom: 18
    }).addTo(attackMap);
}

// Load geolocation data for the map
async function loadGeoLocations() {
    try {
        const response = await fetch('/api/geo-locations');
        const data = await response.json();
        
        // Clear existing markers
        attackMap.eachLayer(layer => {
            if (layer instanceof L.Marker || layer instanceof L.MarkerClusterGroup) {
                attackMap.removeLayer(layer);
            }
        });
        
        // Create marker cluster group
        const markers = L.markerClusterGroup({
            maxClusterRadius: 50,
            iconCreateFunction: function(cluster) {
                const count = cluster.getChildCount();
                let size = 'small';
                if (count > 50) size = 'large';
                else if (count > 20) size = 'medium';
                
                return L.divIcon({
                    html: '<div><span>' + count + '</span></div>',
                    className: 'marker-cluster marker-cluster-' + size,
                    iconSize: L.point(40, 40)
                });
            }
        });
        
        // Add markers for each location
        data.forEach(location => {
            const marker = L.marker([location.lat, location.lng])
                .bindPopup(`
                    <strong>${location.ip}</strong><br>
                    ${location.city}, ${location.country}<br>
                    <strong>Requests:</strong> ${location.count}
                    <br><br><em>Click marker to view requests</em>
                `);
            
            // Add click handler to open modal with IP requests
            marker.on('click', () => {
                openRequestModal('ip', location.ip, `Requests from ${location.ip} (${location.city}, ${location.country})`);
            });
            
            markers.addLayer(marker);
        });
        
        attackMap.addLayer(markers);
        
        // Fit bounds to show all markers if data exists
        if (data.length > 0) {
            const bounds = markers.getBounds();
            attackMap.fitBounds(bounds, { padding: [50, 50] });
        }
        
    } catch (error) {
        console.error('Error loading geo locations:', error);
    }
}
