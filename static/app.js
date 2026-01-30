// Theron Dashboard - Simple & Friendly

class TheronDashboard {
    constructor() {
        this.ws = null;
        this.blockedActions = [];
        this.init();
    }

    init() {
        this.loadStats();
        this.loadRecentBlocks();
        this.connectWebSocket();
    }

    // WebSocket for real-time updates
    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/api/events/stream`;

        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                this.setConnected(true);
            };

            this.ws.onclose = () => {
                this.setConnected(false);
                setTimeout(() => this.connectWebSocket(), 5000);
            };

            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleMessage(data);
            };
        } catch (error) {
            this.setConnected(false);
            setTimeout(() => this.connectWebSocket(), 5000);
        }
    }

    setConnected(connected) {
        const dot = document.getElementById('connection-dot');
        dot.classList.toggle('connected', connected);
        dot.title = connected ? 'Connected' : 'Disconnected';
    }

    handleMessage(data) {
        if (data.type === 'stats_update') {
            this.updateStats(data.data);
        } else if (data.type === 'sandbox_blocked') {
            this.addBlockedItem(data.data);
        }
    }

    // Load stats
    async loadStats() {
        try {
            const response = await fetch('/api/stats');
            const data = await response.json();
            this.updateStats(data);
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

    updateStats(data) {
        const summary = data.summary || {};
        document.getElementById('threats-blocked').textContent =
            this.formatNumber(summary.blocked_count || 0);
        document.getElementById('requests-checked').textContent =
            this.formatNumber(summary.total_events || 0);
    }

    formatNumber(num) {
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
        return num.toString();
    }

    // Load recent blocks
    async loadRecentBlocks() {
        try {
            const response = await fetch('/api/sandbox/blocked');
            const data = await response.json();
            this.blockedActions = data.results || [];
            this.renderRecentBlocks();
        } catch (error) {
            console.error('Failed to load blocked actions:', error);
        }
    }

    addBlockedItem(action) {
        this.blockedActions.unshift(action);
        if (this.blockedActions.length > 10) {
            this.blockedActions.pop();
        }
        this.renderRecentBlocks();
    }

    renderRecentBlocks() {
        const list = document.getElementById('recent-list');

        if (this.blockedActions.length === 0) {
            list.innerHTML = `
                <div class="empty-state">
                    <p>Nothing blocked yet. You're all clear!</p>
                </div>
            `;
            return;
        }

        list.innerHTML = this.blockedActions.slice(0, 5).map(action => {
            const time = this.formatTime(new Date(action.created_at));
            const name = this.escapeHtml(String(action.tool_name || 'Dangerous action'));
            return `
                <div class="recent-item">
                    <span class="recent-dot"></span>
                    <span class="recent-text">Blocked: ${name}</span>
                    <span class="recent-time">${time}</span>
                </div>
            `;
        }).join('');
    }

    formatTime(date) {
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMins / 60);
        const diffDays = Math.floor(diffHours / 24);

        if (diffMins < 1) return 'now';
        if (diffMins < 60) return `${diffMins}m`;
        if (diffHours < 24) return `${diffHours}h`;
        if (diffDays < 7) return `${diffDays}d`;
        return date.toLocaleDateString();
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Start
document.addEventListener('DOMContentLoaded', () => {
    new TheronDashboard();
});
