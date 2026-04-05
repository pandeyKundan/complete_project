// Main JavaScript file for common functionality

document.addEventListener('DOMContentLoaded', function() {
    // Mobile menu toggle
    const mobileMenuToggle = document.createElement('button');
    mobileMenuToggle.className = 'mobile-menu-toggle';
    mobileMenuToggle.innerHTML = '<i class="fas fa-bars"></i>';
    mobileMenuToggle.style.cssText = `
        position: fixed;
        top: 1rem;
        right: 1rem;
        z-index: 1001;
        background: var(--primary);
        color: white;
        border: none;
        border-radius: 4px;
        width: 40px;
        height: 40px;
        display: none;
        align-items: center;
        justify-content: center;
        cursor: pointer;
    `;
    
    document.body.appendChild(mobileMenuToggle);
    
    mobileMenuToggle.addEventListener('click', function() {
        const sidebar = document.querySelector('.sidebar');
        if (sidebar) {
            sidebar.classList.toggle('active');
        }
        
        const navMenu = document.querySelector('.nav-menu');
        if (navMenu) {
            navMenu.classList.toggle('active');
        }
    });
    
    // Check for mobile
    function checkMobile() {
        if (window.innerWidth <= 768) {
            mobileMenuToggle.style.display = 'flex';
            document.querySelectorAll('.nav-menu').forEach(menu => {
                menu.classList.add('mobile-hidden');
            });
        } else {
            mobileMenuToggle.style.display = 'none';
            document.querySelectorAll('.nav-menu').forEach(menu => {
                menu.classList.remove('mobile-hidden');
            });
        }
    }
    
    checkMobile();
    window.addEventListener('resize', checkMobile);
    
    // Dropdown functionality
    document.querySelectorAll('.dropdown').forEach(dropdown => {
        dropdown.addEventListener('click', function(e) {
            e.stopPropagation();
            this.classList.toggle('active');
        });
    });
    
    // Close dropdowns when clicking outside
    document.addEventListener('click', function() {
        document.querySelectorAll('.dropdown').forEach(dropdown => {
            dropdown.classList.remove('active');
        });
    });
    
    // Update active navigation
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.nav-menu a').forEach(link => {
        const linkPage = link.getAttribute('href');
        if (linkPage === currentPage) {
            link.classList.add('active');
        }
    });
    
    document.querySelectorAll('.sidebar-link').forEach(link => {
        const linkPage = link.getAttribute('href');
        if (linkPage === currentPage) {
            link.classList.add('active');
        }
    });
    
    // Add animation to cards on scroll
    const animatedCards = document.querySelectorAll('.card, .feature-card, .report-card');
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animated');
            }
        });
    }, { threshold: 0.1 });
    
    animatedCards.forEach(card => {
        observer.observe(card);
    });
    
    // Create cyber security background elements
    createCyberBackground();
});

function createCyberBackground() {
    const container = document.querySelector('body');
    
    // Create floating cyber elements
    for (let i = 0; i < 20; i++) {
        const element = document.createElement('div');
        element.className = 'cyber-element';
        element.style.cssText = `
            position: fixed;
            width: ${Math.random() * 4 + 1}px;
            height: ${Math.random() * 4 + 1}px;
            background: var(--primary);
            border-radius: 50%;
            opacity: ${Math.random() * 0.3 + 0.1};
            top: ${Math.random() * 100}%;
            left: ${Math.random() * 100}%;
            pointer-events: none;
            z-index: -1;
            animation: float ${Math.random() * 10 + 10}s linear infinite;
        `;
        container.appendChild(element);
    }
    
    // Add CSS for animation
    const style = document.createElement('style');
    style.textContent = `
        @keyframes float {
            0% {
                transform: translateY(0) translateX(0);
            }
            25% {
                transform: translateY(-100px) translateX(100px);
            }
            50% {
                transform: translateY(-200px) translateX(0);
            }
            75% {
                transform: translateY(-100px) translateX(-100px);
            }
            100% {
                transform: translateY(0) translateX(0);
            }
        }
        
        .mobile-hidden {
            display: none;
        }
        
        @media (min-width: 769px) {
            .mobile-hidden {
                display: flex !important;
            }
        }
    `;
    document.head.appendChild(style);
}

// Utility functions
function formatDate(date) {
    return new Date(date).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

function formatTime(date) {
    return new Date(date).toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit'
    });
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'success' ? '#4caf50' : type === 'error' ? '#ff3e41' : '#2a75ff'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 4px;
        z-index: 10000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
    
    // Add animation CSS
    if (!document.querySelector('#notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
            @keyframes slideOut {
                from { transform: translateX(0); opacity: 1; }
                to { transform: translateX(100%); opacity: 0; }
            }
        `;
        document.head.appendChild(style);
    }
}
