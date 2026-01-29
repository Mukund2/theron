// Theron Dashboard Application

class TheronDashboard {
    constructor() {
        this.ws = null;
        this.events = [];
        this.blockedActions = [];
        this.config = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;

        this.init();
    }

    init() {
        // Initialize tabs
        this.initTabs();

        // Initialize filters
        this.initFilters();

        // Initialize config controls
        this.initConfig();

        // Initialize sandbox controls
        this.initSandbox();

        // Load initial data
        this.loadEvents();
        this.loadStats();
        this.loadConfig();
        this.loadBlockedActions();
        this.checkSandboxStatus();

        // Connect WebSocket
        this.connectWebSocket();
    }

    // Tab Management
    initTabs() {
        const tabs = document.querySelectorAll('.tab');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const tabId = tab.dataset.tab;
                this.switchTab(tabId);
            });
        });
    }

    switchTab(tabId) {
        // Update tab buttons
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelector(`[data-tab="${tabId}"]`).classList.add('active');

        // Update panels
        document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
        document.getElementById(`${tabId}-panel`).classList.add('active');

        // Load data for the tab
        if (tabId === 'stats') {
            this.loadStats();
        } else if (tabId === 'config') {
            this.loadConfig();
        } else if (tabId === 'blocked') {
            this.loadBlockedActions();
        }
    }

    // Filter Management
    initFilters() {
        document.getElementById('filter-action').addEventListener('change', () => this.loadEvents());
        document.getElementById('filter-tier').addEventListener('change', () => this.loadEvents());
        document.getElementById('refresh-events').addEventListener('click', () => this.loadEvents());
    }

    // WebSocket Connection
    connectWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/api/events/stream`;

        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                console.log('WebSocket connected');
                this.updateConnectionStatus(true);
                this.reconnectAttempts = 0;
            };

            this.ws.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateConnectionStatus(false);
                this.scheduleReconnect();
            };

            this.ws.onerror = (error) => {
                console.error('WebSocket error:', error);
            };

            this.ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                this.handleWebSocketMessage(data);
            };
        } catch (error) {
            console.error('Failed to connect WebSocket:', error);
            this.scheduleReconnect();
        }
    }

    scheduleReconnect() {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
            console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
            setTimeout(() => this.connectWebSocket(), delay);
        }
    }

    updateConnectionStatus(connected) {
        const status = document.getElementById('connection-status');
        if (connected) {
            status.classList.add('connected');
            status.classList.remove('disconnected');
            status.querySelector('.text').textContent = 'Connected';
        } else {
            status.classList.remove('connected');
            status.classList.add('disconnected');
            status.querySelector('.text').textContent = 'Disconnected';
        }
    }

    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'new_event':
                this.addEvent(data.data);
                break;
            case 'stats_update':
                this.updateStats(data.data);
                break;
            case 'alert':
                this.showAlert(data.data);
                break;
            case 'connected':
                console.log('WebSocket:', data.message);
                break;
            case 'sandbox_blocked':
                this.addBlockedAction(data.data);
                // Sanitize tool_name for alert message
                const toolName = String(data.data?.tool_name || 'unknown').substring(0, 50);
                this.showAlert({
                    level: 'warning',
                    message: `Blocked dangerous action: ${toolName}`,
                });
                break;
        }
    }

    // Event Management
    async loadEvents() {
        const action = document.getElementById('filter-action').value;
        const tier = document.getElementById('filter-tier').value;

        const params = new URLSearchParams();
        if (action) params.append('action', action);
        if (tier) params.append('risk_tier', tier);
        params.append('limit', '100');

        try {
            const response = await fetch(`/api/events?${params}`);
            const data = await response.json();
            this.events = data.events || [];
            this.renderEvents();
        } catch (error) {
            console.error('Failed to load events:', error);
            this.renderEventsError();
        }
    }

    addEvent(event) {
        // Add to beginning of list
        this.events.unshift(event);
        // Keep only last 100
        if (this.events.length > 100) {
            this.events.pop();
        }
        this.renderEvents();
    }

    renderEvents() {
        const container = document.getElementById('event-list');

        if (this.events.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <h3>No events yet</h3>
                    <p>Events will appear here when your AI agent makes API calls through Theron.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = this.events.map(event => this.renderEventItem(event)).join('');
    }

    renderEventItem(event) {
        const timestamp = new Date(event.timestamp).toLocaleTimeString();
        // Sanitize class names to prevent injection
        const sourceTag = String(event.source_tag || 'unknown');
        const sourceTagClass = sourceTag.toLowerCase().replace(/[^a-z0-9-]/g, '-');
        const riskTier = parseInt(event.risk_tier) || 0;
        const riskTierClass = `tier-${riskTier}`;
        const action = String(event.action || 'allowed');
        const actionClass = action.toLowerCase().replace(/[^a-z]/g, '');
        const threatScore = parseInt(event.threat_score) || 0;
        const threatScoreClass = threatScore >= 70 ? 'high' : '';

        return `
            <div class="event-item ${actionClass}">
                <span class="timestamp">${this.escapeHtml(timestamp)}</span>
                <span class="agent">${this.escapeHtml(String(event.agent_id || 'unknown'))}</span>
                <span class="source-tag ${sourceTagClass}">${this.escapeHtml(sourceTag)}</span>
                <span class="tool-name">${this.escapeHtml(String(event.tool_name || '-'))}</span>
                <span class="risk-tier ${riskTierClass}">Tier ${riskTier || '-'}</span>
                <span class="action-badge ${actionClass}">${this.escapeHtml(action)}</span>
                <span class="threat-score ${threatScoreClass}">${threatScore}</span>
            </div>
        `;
    }

    renderEventsError() {
        const container = document.getElementById('event-list');
        container.innerHTML = `
            <div class="empty-state">
                <h3>Failed to load events</h3>
                <p>Please check that the Theron server is running.</p>
            </div>
        `;
    }

    // Statistics
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
        document.getElementById('stat-total').textContent = summary.total_events || 0;
        document.getElementById('stat-blocked').textContent = summary.blocked_count || 0;
        document.getElementById('stat-injections').textContent = summary.injection_count || 0;
        document.getElementById('stat-agents').textContent = summary.unique_agents || 0;

        // Render daily chart
        this.renderDailyChart(data.daily || []);
    }

    renderDailyChart(daily) {
        const chart = document.getElementById('daily-chart');
        if (daily.length === 0) {
            chart.innerHTML = '<div class="empty-state">No data available</div>';
            return;
        }

        const maxValue = Math.max(...daily.map(d => d.total_requests || 0), 1);

        chart.innerHTML = daily.slice(0, 7).reverse().map(day => {
            const totalRequests = parseInt(day.total_requests) || 0;
            const height = Math.max((totalRequests / maxValue) * 100, 5);
            const dateObj = new Date(day.date);
            // Validate date is valid before formatting
            const date = isNaN(dateObj.getTime()) ? 'N/A' : dateObj.toLocaleDateString('en-US', { weekday: 'short' });
            return `
                <div class="chart-bar" style="height: ${height}%">
                    <span class="chart-value">${totalRequests}</span>
                    <span class="chart-label">${this.escapeHtml(date)}</span>
                </div>
            `;
        }).join('');
    }

    // Configuration
    initConfig() {
        // Sensitivity slider
        const sensitivitySlider = document.getElementById('config-sensitivity');
        const sensitivityValue = document.getElementById('sensitivity-value');
        sensitivitySlider.addEventListener('input', () => {
            sensitivityValue.textContent = sensitivitySlider.value;
        });

        // Save button
        document.getElementById('save-config').addEventListener('click', () => this.saveConfig());

        // Reset button
        document.getElementById('reset-config').addEventListener('click', () => this.loadConfig());
    }

    async loadConfig() {
        try {
            const response = await fetch('/api/config');
            this.config = await response.json();
            this.renderConfig();
        } catch (error) {
            console.error('Failed to load config:', error);
        }
    }

    renderConfig() {
        if (!this.config) return;

        // Detection settings
        document.getElementById('config-sensitivity').value = this.config.detection?.sensitivity || 5;
        document.getElementById('sensitivity-value').textContent = this.config.detection?.sensitivity || 5;
        document.getElementById('config-threshold').value = this.config.detection?.injection_threshold || 70;

        // Categories
        const categoriesGrid = document.getElementById('categories-grid');
        const categories = this.config.detection?.categories || {};
        categoriesGrid.innerHTML = Object.entries(categories).map(([key, enabled]) => {
            // Sanitize key for safe use in id and label
            const safeKey = String(key).replace(/[^a-z0-9_-]/gi, '');
            const displayKey = safeKey.replace(/_/g, ' ');
            return `
                <div class="checkbox-item">
                    <input type="checkbox" id="cat-${safeKey}" ${enabled ? 'checked' : ''}>
                    <label for="cat-${safeKey}">${this.escapeHtml(displayKey)}</label>
                </div>
            `;
        }).join('');

        // Gating
        document.getElementById('config-whitelist').value = (this.config.gating?.whitelist || []).join(', ');
        document.getElementById('config-blacklist').value = (this.config.gating?.blacklist || []).join(', ');
    }

    async saveConfig() {
        // Gather config values
        const categories = {};
        document.querySelectorAll('#categories-grid input[type="checkbox"]').forEach(input => {
            const key = input.id.replace('cat-', '');
            categories[key] = input.checked;
        });

        const whitelist = document.getElementById('config-whitelist').value
            .split(',')
            .map(s => s.trim())
            .filter(s => s);

        const blacklist = document.getElementById('config-blacklist').value
            .split(',')
            .map(s => s.trim())
            .filter(s => s);

        const newConfig = {
            detection: {
                sensitivity: parseInt(document.getElementById('config-sensitivity').value),
                injection_threshold: parseInt(document.getElementById('config-threshold').value),
                categories: categories,
            },
            gating: {
                whitelist: whitelist,
                blacklist: blacklist,
            },
        };

        try {
            const response = await fetch('/api/config', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(newConfig),
            });
            const result = await response.json();

            if (result.status === 'success') {
                this.showAlert({
                    level: 'info',
                    message: 'Configuration saved successfully',
                });
            } else {
                this.showAlert({
                    level: 'error',
                    message: 'Failed to save configuration: ' + result.message,
                });
            }
        } catch (error) {
            console.error('Failed to save config:', error);
            this.showAlert({
                level: 'error',
                message: 'Failed to save configuration',
            });
        }
    }

    // Alerts
    showAlert(data) {
        const toast = document.getElementById('alert-toast');
        // Sanitize level to prevent class injection
        const level = String(data.level || 'info').replace(/[^a-z]/g, '');
        toast.className = `alert-toast ${level}`;

        // Use textContent for safe text insertion (already safe, but being explicit)
        toast.querySelector('.alert-title').textContent = level === 'error' ? 'Error' : 'Alert';
        toast.querySelector('.alert-message').textContent = String(data.message || '');

        toast.classList.remove('hidden');

        // Auto-hide after 5 seconds
        setTimeout(() => {
            toast.classList.add('hidden');
        }, 5000);

        // Close button
        toast.querySelector('.alert-close').onclick = () => {
            toast.classList.add('hidden');
        };
    }

    // Blocked Actions Management
    initSandbox() {
        document.getElementById('refresh-blocked').addEventListener('click', () => {
            this.loadBlockedActions();
        });
    }

    async checkSandboxStatus() {
        try {
            const response = await fetch('/api/sandbox/status');
            const data = await response.json();
            this.updateDockerStatus(data.docker_available);
        } catch (error) {
            console.error('Failed to check sandbox status:', error);
            this.updateDockerStatus(false);
        }
    }

    updateDockerStatus(available) {
        const status = document.getElementById('docker-status');
        if (available) {
            status.classList.add('connected');
            status.classList.remove('disconnected');
            status.querySelector('.text').textContent = 'Docker Available';
        } else {
            status.classList.remove('connected');
            status.classList.add('disconnected');
            status.querySelector('.text').textContent = 'Docker Unavailable';
        }
    }

    async loadBlockedActions() {
        try {
            const response = await fetch('/api/sandbox/blocked');
            const data = await response.json();
            this.blockedActions = data.results || [];
            this.renderBlockedActions();
        } catch (error) {
            console.error('Failed to load blocked actions:', error);
            this.renderBlockedError();
        }
    }

    addBlockedAction(action) {
        this.blockedActions.unshift(action);
        // Keep only last 50
        if (this.blockedActions.length > 50) {
            this.blockedActions.pop();
        }
        this.renderBlockedActions();
    }

    renderBlockedActions() {
        const container = document.getElementById('blocked-list');

        if (this.blockedActions.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <h3>No blocked actions</h3>
                    <p>When dangerous actions from untrusted sources are detected, they are automatically blocked and shown here.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = this.blockedActions.map(action => this.renderBlockedCard(action)).join('');
    }

    renderBlockedCard(action) {
        const timestamp = new Date(action.created_at).toLocaleString();
        const riskTier = parseInt(action.risk_tier) || 3;
        const riskTierClass = `tier-${riskTier}`;
        const riskTierLabel = riskTier === 4 ? 'Critical' : 'Sensitive';
        const threatScore = parseInt(action.threat_score) || 0;
        const exitCode = action.exit_code !== null ? parseInt(action.exit_code) : null;
        const durationMs = parseInt(action.duration_ms) || 0;

        // Sanitize sandbox_id for data attribute (alphanumeric and hyphens only)
        const sandboxId = String(action.sandbox_id || '').replace(/[^a-zA-Z0-9-]/g, '');

        // Format arguments
        let argsDisplay = '';
        if (action.tool_arguments && typeof action.tool_arguments === 'object') {
            argsDisplay = JSON.stringify(action.tool_arguments, null, 2);
        } else if (action.tool_arguments) {
            argsDisplay = String(action.tool_arguments);
        }

        return `
            <div class="blocked-card" data-id="${sandboxId}">
                <div class="blocked-card-header">
                    <div class="tool-info">
                        <span class="tool-name">${this.escapeHtml(String(action.tool_name || 'unknown'))}</span>
                        <span class="risk-badge ${riskTierClass}">Tier ${riskTier} - ${riskTierLabel}</span>
                        <span class="blocked-badge">BLOCKED</span>
                    </div>
                    <span class="timestamp">${this.escapeHtml(timestamp)}</span>
                </div>
                <div class="blocked-card-body">
                    <div class="blocked-command">${this.escapeHtml(String(action.command || ''))}</div>

                    ${argsDisplay ? `
                    <div class="blocked-output">
                        <div class="blocked-output-label">Arguments</div>
                        <div class="blocked-output-content">${this.escapeHtml(argsDisplay)}</div>
                    </div>
                    ` : ''}

                    ${action.stdout ? `
                    <div class="blocked-output">
                        <div class="blocked-output-label">Sandbox Output (would have produced)</div>
                        <div class="blocked-output-content">${this.escapeHtml(String(action.stdout))}</div>
                    </div>
                    ` : ''}

                    ${action.stderr ? `
                    <div class="blocked-output">
                        <div class="blocked-output-label">Sandbox Errors</div>
                        <div class="blocked-output-content stderr">${this.escapeHtml(String(action.stderr))}</div>
                    </div>
                    ` : ''}

                    <div class="blocked-meta">
                        <div class="blocked-meta-item">
                            <span>Source:</span>
                            <strong>${this.escapeHtml(String(action.source_tag || 'Unknown'))}</strong>
                        </div>
                        <div class="blocked-meta-item">
                            <span>Threat Score:</span>
                            <strong>${threatScore}</strong>
                        </div>
                        <div class="blocked-meta-item">
                            <span>Exit Code:</span>
                            <strong>${exitCode !== null ? exitCode : 'N/A'}</strong>
                        </div>
                        <div class="blocked-meta-item">
                            <span>Duration:</span>
                            <strong>${durationMs}ms</strong>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderBlockedError() {
        const container = document.getElementById('blocked-list');
        container.innerHTML = `
            <div class="empty-state">
                <h3>Failed to load blocked actions</h3>
                <p>Please check that the Theron server is running.</p>
            </div>
        `;
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new TheronDashboard();
});
