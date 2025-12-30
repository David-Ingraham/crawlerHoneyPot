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
                    position: 'bottom',
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
    
    // Update categories chart
    updateChart(categoriesChart, 
        data.categories.map(c => c.name),
        data.categories.map(c => c.count)
    );
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


