// Dashboard JavaScript
// Handles real-time data updates and chart rendering

// Chart instances
let categoriesChart, attackTypesChart, topIpsChart, topPathsChart, timelineChart;

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
    loadAllData();
    
    // Refresh data every 30 seconds
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

// Load all data
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
    
    updateChart(topIpsChart,
        data.map(item => item.ip),
        data.map(item => item.count)
    );
}

// Load top paths
async function loadTopPaths() {
    const response = await fetch('/api/top-paths');
    const data = await response.json();
    
    // Truncate long paths
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
            openThreatModal(threatLevel);
        });
    });
});

// Open modal
function openThreatModal(threatLevel) {
    const titles = {
        'benign': 'Benign Traffic Analysis',
        'reconnaissance': 'Reconnaissance Traffic Analysis',
        'malicious': 'Malicious Traffic Analysis'
    };
    
    modalTitle.textContent = titles[threatLevel] || 'Traffic Analysis';
    modal.classList.add('active');
    document.body.style.overflow = 'hidden';
    
    // Show loading state
    modalLoading.style.display = 'block';
    modalRequests.style.display = 'none';
    modalRequests.innerHTML = '';
    
    // Fetch data
    loadThreatRequests(threatLevel);
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

// Load threat requests
async function loadThreatRequests(threatLevel) {
    try {
        const response = await fetch(`/api/requests-by-threat/${threatLevel}`);
        const requests = await response.json();
        
        modalLoading.style.display = 'none';
        modalRequests.style.display = 'block';
        
        if (requests.length === 0) {
            modalRequests.innerHTML = '<div class="modal-loading">No requests found for this threat level</div>';
            return;
        }
        
        // Update title with count
        const baseTitle = modalTitle.textContent.split(' - ')[0];
        modalTitle.textContent = `${baseTitle} - Showing ${requests.length} requests`;
        
        // Build request cards
        modalRequests.innerHTML = requests.map(req => createRequestCard(req)).join('');
    } catch (error) {
        console.error('Error loading threat requests:', error);
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
    
    return `
        <div class="request-card">
            <div class="request-header">
                <div class="request-meta">
                    <span class="request-time">${escapeHtml(request.timestamp)}</span>
                    <span class="request-ip">${escapeHtml(request.ip)}</span>
                </div>
                <div class="threat-badge ${request.threat_level}">
                    ${request.threat_level} - Score: ${request.threat_score}
                </div>
            </div>
            
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
