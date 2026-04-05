// Dashboard specific JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize real-time updates
    initRealTimeUpdates();
    
    // Setup event listeners
    setupDashboardEvents();
    
    // Load initial data
    loadDashboardData();
});

function initRealTimeUpdates() {
    // Simulate real-time updates
    setInterval(() => {
        updateLiveStats();
    }, 10000);
}

function setupDashboardEvents() {
    // Quick scan button
    const quickScanBtn = document.querySelector('.btn-primary');
    if (quickScanBtn) {
        quickScanBtn.addEventListener('click', function() {
            showNotification('Starting quick security scan...', 'info');
            simulateQuickScan();
        });
    }
    
    // Fix critical issues button
    const fixCriticalBtn = document.querySelector('.btn-danger');
    if (fixCriticalBtn) {
        fixCriticalBtn.addEventListener('click', function() {
            showNotification('Fixing critical issues...', 'success');
            setTimeout(() => {
                document.querySelectorAll('.issue-item.critical').forEach(item => {
                    item.style.opacity = '0.5';
                    item.querySelector('.btn-danger').textContent = 'Fixed';
                    item.querySelector('.btn-danger').classList.remove('btn-danger');
                    item.querySelector('.btn-danger').classList.add('btn-success');
                });
            }, 2000);
        });
    }
    
    // Period selector
    const periodSelect = document.querySelector('.period-select');
    if (periodSelect) {
        periodSelect.addEventListener('change', function() {
            updateCharts(this.value);
        });
    }
}

function loadDashboardData() {
    // Simulate loading data from API
    setTimeout(() => {
        updateLiveStats();
    }, 1000);
}

function updateLiveStats() {
    // Simulate live data updates
    const stats = {
        securityScore: Math.floor(Math.random() * 5 + 95),
        criticalIssues: Math.floor(Math.random() * 5),
        totalVulnerabilities: Math.floor(Math.random() * 10 + 20)
    };
    
    // Update DOM elements
    const scoreElement = document.querySelector('.stat-card:nth-child(1) h3');
    if (scoreElement) scoreElement.textContent = stats.securityScore + '%';
    
    const criticalElement = document.querySelector('.stat-card:nth-child(2) h3');
    if (criticalElement) criticalElement.textContent = stats.criticalIssues;
    
    const vulnElement = document.querySelector('.stat-card:nth-child(3) h3');
    if (vulnElement) vulnElement.textContent = stats.totalVulnerabilities;
}

function simulateQuickScan() {
    const scanBtn = document.querySelector('.btn-primary');
    const originalText = scanBtn.innerHTML;
    
    scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Scanning...';
    scanBtn.disabled = true;
    
    // Simulate scan progress
    let progress = 0;
    const interval = setInterval(() => {
        progress += 10;
        scanBtn.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Scanning... ${progress}%`;
        
        if (progress >= 100) {
            clearInterval(interval);
            scanBtn.innerHTML = originalText;
            scanBtn.disabled = false;
            showNotification('Quick scan completed!', 'success');
            
            // Update dashboard
            updateLiveStats();
        }
    }, 300);
}

function updateCharts(period) {
    // In a real app, this would fetch new data and update charts
    console.log('Updating charts for period:', period);
    showNotification(`Charts updated for ${period}`, 'info');
}
