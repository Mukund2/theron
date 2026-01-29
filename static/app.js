// Theron Dashboard Application

class TheronDashboard {
    constructor() {
        this.ws = null;
        this.events = [];
        this.pendingSandbox = [];
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
        this.loadPendingSandbox();
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
        } else if (tabId === 'approvals') {
            this.loadPendingSandbox();
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
            case 'sandbox_pending':
                this.addPendingSandbox(data.data);
                this.showAlert({
                    level: 'warning',
                    message: `New action pending approval: ${data.data.tool_name}`,
                });
                break;
            case 'sandbox_approved':
                this.removePendingSandbox(data.data.sandbox_id);
                break;
            case 'sandbox_rejected':
                this.removePendingSandbox(data.data.sandbox_id);
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
        const sourceTagClass = (event.source_tag || 'unknown').toLowerCase().replace('_', '-');
        const riskTierClass = `tier-${event.risk_tier || 0}`;
        const actionClass = (event.action || 'allowed').toLowerCase();
        const threatScoreClass = (event.threat_score || 0) >= 70 ? 'high' : '';

        return `
            <div class="event-item ${actionClass}">
                <span class="timestamp">${timestamp}</span>
                <span class="agent">${event.agent_id || 'unknown'}</span>
                <span class="source-tag ${sourceTagClass}">${event.source_tag || 'N/A'}</span>
                <span class="tool-name">${event.tool_name || '-'}</span>
                <span class="risk-tier ${riskTierClass}">Tier ${event.risk_tier || '-'}</span>
                <span class="action-badge ${actionClass}">${event.action || 'allowed'}</span>
                <span class="threat-score ${threatScoreClass}">${event.threat_score || 0}</span>
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
            const height = Math.max(((day.total_requests || 0) / maxValue) * 100, 5);
            const date = new Date(day.date).toLocaleDateString('en-US', { weekday: 'short' });
            return `
                <div class="chart-bar" style="height: ${height}%">
                    <span class="chart-value">${day.total_requests || 0}</span>
                    <span class="chart-label">${date}</span>
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
        categoriesGrid.innerHTML = Object.entries(categories).map(([key, enabled]) => `
            <div class="checkbox-item">
                <input type="checkbox" id="cat-${key}" ${enabled ? 'checked' : ''}>
                <label for="cat-${key}">${key.replace(/_/g, ' ')}</label>
            </div>
        `).join('');

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
        toast.className = `alert-toast ${data.level || 'info'}`;

        toast.querySelector('.alert-title').textContent = data.level === 'error' ? 'Error' : 'Alert';
        toast.querySelector('.alert-message').textContent = data.message;

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

    // Sandbox Management
    initSandbox() {
        document.getElementById('refresh-approvals').addEventListener('click', () => {
            this.loadPendingSandbox();
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

    async loadPendingSandbox() {
        try {
            const response = await fetch('/api/sandbox/pending');
            const data = await response.json();
            this.pendingSandbox = data.results || [];
            this.renderPendingSandbox();
            this.updatePendingCount();
        } catch (error) {
            console.error('Failed to load pending sandbox:', error);
            this.renderSandboxError();
        }
    }

    addPendingSandbox(sandbox) {
        this.pendingSandbox.unshift(sandbox);
        this.renderPendingSandbox();
        this.updatePendingCount();
    }

    removePendingSandbox(sandboxId) {
        this.pendingSandbox = this.pendingSandbox.filter(s => s.sandbox_id !== sandboxId);
        this.renderPendingSandbox();
        this.updatePendingCount();
    }

    updatePendingCount() {
        const badge = document.getElementById('pending-count');
        const count = this.pendingSandbox.length;
        badge.textContent = count;
        if (count > 0) {
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }
    }

    renderPendingSandbox() {
        const container = document.getElementById('approvals-list');

        if (this.pendingSandbox.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <h3>No pending approvals</h3>
                    <p>When sensitive actions from untrusted sources are detected, they will be sandboxed and shown here for your approval.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = this.pendingSandbox.map(sandbox => this.renderSandboxCard(sandbox)).join('');

        // Attach event listeners
        container.querySelectorAll('.btn-approve').forEach(btn => {
            btn.addEventListener('click', () => this.approveSandbox(btn.dataset.id));
        });
        container.querySelectorAll('.btn-reject').forEach(btn => {
            btn.addEventListener('click', () => this.rejectSandbox(btn.dataset.id));
        });
    }

    renderSandboxCard(sandbox) {
        const timestamp = new Date(sandbox.created_at).toLocaleString();
        const riskTierClass = `tier-${sandbox.risk_tier || 3}`;
        const riskTierLabel = sandbox.risk_tier === 4 ? 'Critical' : 'Sensitive';

        // Format arguments
        let argsDisplay = '';
        if (sandbox.tool_arguments && typeof sandbox.tool_arguments === 'object') {
            argsDisplay = JSON.stringify(sandbox.tool_arguments, null, 2);
        } else if (sandbox.tool_arguments) {
            argsDisplay = String(sandbox.tool_arguments);
        }

        return `
            <div class="sandbox-card" data-id="${sandbox.sandbox_id}">
                <div class="sandbox-card-header">
                    <div class="tool-info">
                        <span class="tool-name">${sandbox.tool_name}</span>
                        <span class="risk-badge ${riskTierClass}">Tier ${sandbox.risk_tier} - ${riskTierLabel}</span>
                    </div>
                    <span class="timestamp">${timestamp}</span>
                </div>
                <div class="sandbox-card-body">
                    <div class="sandbox-command">${this.escapeHtml(sandbox.command)}</div>

                    ${argsDisplay ? `
                    <div class="sandbox-output">
                        <div class="sandbox-output-label">Arguments</div>
                        <div class="sandbox-output-content">${this.escapeHtml(argsDisplay)}</div>
                    </div>
                    ` : ''}

                    ${sandbox.stdout ? `
                    <div class="sandbox-output">
                        <div class="sandbox-output-label">Output (stdout)</div>
                        <div class="sandbox-output-content">${this.escapeHtml(sandbox.stdout)}</div>
                    </div>
                    ` : ''}

                    ${sandbox.stderr ? `
                    <div class="sandbox-output">
                        <div class="sandbox-output-label">Errors (stderr)</div>
                        <div class="sandbox-output-content stderr">${this.escapeHtml(sandbox.stderr)}</div>
                    </div>
                    ` : ''}

                    <div class="sandbox-meta">
                        <div class="sandbox-meta-item">
                            <span>Source:</span>
                            <strong>${sandbox.source_tag || 'Unknown'}</strong>
                        </div>
                        <div class="sandbox-meta-item">
                            <span>Threat Score:</span>
                            <strong>${sandbox.threat_score || 0}</strong>
                        </div>
                        <div class="sandbox-meta-item">
                            <span>Exit Code:</span>
                            <strong>${sandbox.exit_code !== null ? sandbox.exit_code : 'N/A'}</strong>
                        </div>
                        <div class="sandbox-meta-item">
                            <span>Duration:</span>
                            <strong>${sandbox.duration_ms || 0}ms</strong>
                        </div>
                    </div>

                    <div class="sandbox-actions">
                        <button class="btn btn-reject" data-id="${sandbox.sandbox_id}">Reject</button>
                        <button class="btn btn-approve" data-id="${sandbox.sandbox_id}">Approve & Execute</button>
                    </div>
                </div>
            </div>
        `;
    }

    async approveSandbox(sandboxId) {
        try {
            const response = await fetch(`/api/sandbox/${sandboxId}/approve`, {
                method: 'POST',
            });
            const result = await response.json();

            if (result.status === 'success') {
                this.showAlert({
                    level: 'info',
                    message: 'Action approved and will be executed',
                });
                this.removePendingSandbox(sandboxId);
            } else {
                this.showAlert({
                    level: 'error',
                    message: result.detail || 'Failed to approve action',
                });
            }
        } catch (error) {
            console.error('Failed to approve sandbox:', error);
            this.showAlert({
                level: 'error',
                message: 'Failed to approve action',
            });
        }
    }

    async rejectSandbox(sandboxId) {
        try {
            const response = await fetch(`/api/sandbox/${sandboxId}/reject`, {
                method: 'POST',
            });
            const result = await response.json();

            if (result.status === 'success') {
                this.showAlert({
                    level: 'info',
                    message: 'Action rejected',
                });
                this.removePendingSandbox(sandboxId);
            } else {
                this.showAlert({
                    level: 'error',
                    message: result.detail || 'Failed to reject action',
                });
            }
        } catch (error) {
            console.error('Failed to reject sandbox:', error);
            this.showAlert({
                level: 'error',
                message: 'Failed to reject action',
            });
        }
    }

    renderSandboxError() {
        const container = document.getElementById('approvals-list');
        container.innerHTML = `
            <div class="empty-state">
                <h3>Failed to load approvals</h3>
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
