/**
 * AegisNet SOC - System Logs, Security Logs & Authentication Controller
 */

class AegisLogsManager {
  constructor(app) {
    this.app = app;
    this.currentTab = 'network'; // 'network', 'system', 'security', 'logins', 'split'
    
    // System Logs State
    this.systemLogs = [];
    this.systemFilterLevel = 'ALL';
    this.systemFilterSearch = '';
    this.systemLiveTail = true;
    this.systemPollTimer = null;

    // Security Logs State
    this.securityLogs = [];
    this.securityFilterCategory = 'ALL';
    this.securityFilterSeverity = 'ALL';
    this.securityFilterSearch = '';

    // Login Attempts State
    this.loginAttempts = [];
    this.activeSessions = [];
    this.loginFilterStatus = 'ALL';
    this.loginFilterSearch = '';
    this.authStats = {};

    this.selectedEvent = null;
    window.aegisLogs = this;

    this.init();
  }

  init() {
    this.bindTabEvents();
    this.bindSystemLogEvents();
    this.bindSecurityLogEvents();
    this.bindLoginEvents();
    this.bindModalEvents();

    // Initial fetch of logs
    this.refreshAllLogs();

    // Check URL hash on startup (e.g. #system, #security, #logins)
    this.handleHashRouting();

    // Polling interval for live logs (every 4 seconds for fresh tailing)
    setInterval(() => {
      if (this.currentTab === 'system' || this.currentTab === 'split') {
        this.fetchSystemLogs(false);
      } else if (this.currentTab === 'security') {
        this.fetchSecurityLogs(false);
      } else if (this.currentTab === 'logins') {
        this.fetchLoginAttempts(false);
      }
    }, 3500);
  }

  // =========================================================================
  // TAB NAVIGATION & HASH ROUTING
  // =========================================================================
  bindTabEvents() {
    // Listen for clicks on all tab buttons (both in header and sub-bars)
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('.soc-nav-tab');
      if (btn) {
        const tab = btn.getAttribute('data-tab');
        if (tab) this.switchTab(tab);
      }
    });

    // KPI Card Click Shortcuts to tabs
    const kpiSystem = document.getElementById('kpiCardSystemLogs');
    if (kpiSystem) kpiSystem.addEventListener('click', () => this.switchTab('system'));

    const kpiSecurity = document.getElementById('kpiCardSecurityLogs');
    if (kpiSecurity) kpiSecurity.addEventListener('click', () => this.switchTab('security'));

    const kpiLogins = document.getElementById('kpiCardLoginAttempts');
    if (kpiLogins) kpiLogins.addEventListener('click', () => this.switchTab('logins'));

    // Hash change event listener
    window.addEventListener('hashchange', () => this.handleHashRouting());
  }

  handleHashRouting() {
    const rawHash = (window.location.hash || '').replace('#', '').toLowerCase().trim();
    if (!rawHash) return;

    if (['system', 'security', 'logins', 'split', 'network'].includes(rawHash)) {
      this.switchTab(rawHash, false);
    } else if (rawHash === 'logs' || rawHash === 'sys') {
      this.switchTab('system', false);
    } else if (rawHash === 'threats' || rawHash === 'sec') {
      this.switchTab('security', false);
    } else if (rawHash === 'auth' || rawHash === 'login') {
      this.switchTab('logins', false);
    }
  }

  switchTab(tabName, updateHash = true) {
    if (!['network', 'system', 'security', 'logins', 'split'].includes(tabName)) return;
    this.currentTab = tabName;

    if (updateHash) {
      history.replaceState(null, null, '#' + tabName);
    }

    // Update All Tab Buttons UI (both Header Pills and Sub-Tab Bar)
    document.querySelectorAll('.soc-nav-tab').forEach(btn => {
      const active = btn.getAttribute('data-tab') === tabName;
      const isHeaderPill = btn.classList.contains('header-nav-tab');

      if (isHeaderPill) {
        if (active) {
          btn.className = "soc-nav-tab header-nav-tab px-3 py-1 rounded-md font-mono text-xs font-bold transition flex items-center bg-cyan-500/25 text-cyan-300 border border-cyan-400 shadow-[0_0_10px_rgba(6,182,212,0.3)]";
        } else {
          btn.className = "soc-nav-tab header-nav-tab px-3 py-1 rounded-md font-mono text-xs font-medium transition flex items-center text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 border border-transparent";
        }
      } else {
        if (active) {
          btn.className = "soc-nav-tab px-3.5 py-2 rounded-t-lg font-mono text-xs font-bold transition flex items-center border-b-2 border-cyan-400 bg-cyber-800 text-cyan-300";
        } else {
          btn.className = "soc-nav-tab px-3.5 py-2 rounded-t-lg font-mono text-xs font-medium transition flex items-center border-b-2 border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-800/40";
        }
      }
    });

    // Toggle Section Visibility
    const secNetwork = document.getElementById('sectionNetworkRadar');
    const secSystem = document.getElementById('sectionSystemLogs');
    const secSecurity = document.getElementById('sectionSecurityLogs');
    const secLogins = document.getElementById('sectionLoginAttempts');
    const secSplit = document.getElementById('sectionSplitView');

    if (secNetwork) secNetwork.classList.toggle('hidden', !(tabName === 'network'));
    if (secSystem) secSystem.classList.toggle('hidden', !(tabName === 'system'));
    if (secSecurity) secSecurity.classList.toggle('hidden', !(tabName === 'security'));
    if (secLogins) secLogins.classList.toggle('hidden', !(tabName === 'logins'));
    if (secSplit) secSplit.classList.toggle('hidden', !(tabName === 'split'));

    // Invalidate map size if returning to map tab or split view
    if ((tabName === 'network' || tabName === 'split') && this.app && this.app.map && this.app.map.map) {
      setTimeout(() => this.app.map.map.invalidateSize(), 150);
    }

    // Refresh active tab data
    if (tabName === 'system') this.fetchSystemLogs(false);
    if (tabName === 'security') this.fetchSecurityLogs(false);
    if (tabName === 'logins') this.fetchLoginAttempts(false);
    if (tabName === 'split') {
      this.fetchSystemLogs(false);
      this.fetchSecurityLogs(false);
      this.fetchLoginAttempts(false);
    }

    if (window.lucide) window.lucide.createIcons();
  }

  refreshAllLogs() {
    this.fetchSystemLogs(false);
    this.fetchSecurityLogs(false);
    this.fetchLoginAttempts(false);
    this.fetchStats();
  }

  // =========================================================================
  // 1. LIVE SYSTEM LOGS
  // =========================================================================
  bindSystemLogEvents() {
    // Level Filter Pills
    document.querySelectorAll('.sys-level-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.sys-level-pill').forEach(b => {
          b.className = "sys-level-pill px-2.5 py-1 rounded text-xs font-mono transition border border-transparent text-slate-400 hover:text-slate-200";
        });
        btn.className = "sys-level-pill px-2.5 py-1 rounded text-xs font-mono transition border border-cyan-500/50 bg-cyan-500/20 text-cyan-300 font-bold";
        this.systemFilterLevel = btn.getAttribute('data-level');
        this.fetchSystemLogs(true);
      });
    });

    // Search input
    const searchInput = document.getElementById('sysLogSearch');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.systemFilterSearch = e.target.value.trim();
        this.renderSystemLogs();
      });
    }

    // Refresh Button
    const refreshBtn = document.getElementById('sysLogRefreshBtn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        this.fetchSystemLogs(true);
        window.AegisUI.showToast("System logs refreshed from OS", "info");
      });
    }

    // Live Tail Toggle
    const tailBtn = document.getElementById('sysLogTailBtn');
    if (tailBtn) {
      tailBtn.addEventListener('click', () => {
        this.systemLiveTail = !this.systemLiveTail;
        const led = document.getElementById('sysLogTailLed');
        if (led) {
          led.className = this.systemLiveTail 
            ? "w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_#10b981] mr-1.5"
            : "w-2 h-2 rounded-full bg-slate-500 mr-1.5";
        }
        window.AegisUI.showToast(this.systemLiveTail ? "Live tail active (auto-scrolling)" : "Live tail paused", "info");
      });
    }

    // Export JSON Button
    const exportBtn = document.getElementById('sysLogExportBtn');
    if (exportBtn) {
      exportBtn.addEventListener('click', () => this.exportLogsAsJson(this.systemLogs, 'system-logs.json'));
    }
  }

  async fetchSystemLogs(showToast = false) {
    try {
      const url = new URL('/api/logs/system', window.location.origin);
      url.searchParams.set('limit', '120');
      if (this.systemFilterLevel !== 'ALL') url.searchParams.set('level', this.systemFilterLevel);
      if (this.systemFilterSearch) url.searchParams.set('search', this.systemFilterSearch);

      const resp = await fetch(url.toString());
      if (resp.ok) {
        const data = await resp.json();
        this.systemLogs = data.logs || [];
        this.renderSystemLogs();
        if (showToast) window.AegisUI.showToast(`Loaded ${this.systemLogs.length} system events`, "info");
      }
    } catch (e) {
      console.warn("Failed to fetch system logs:", e);
    }
  }

  renderSystemLogs() {
    const tbody = document.getElementById('sysLogsTableBody');
    const splitTbody = document.getElementById('splitSysLogsTableBody');
    if (!tbody && !splitTbody) return;

    let filtered = this.systemLogs;
    if (this.systemFilterSearch) {
      const s = this.systemFilterSearch.toLowerCase();
      filtered = filtered.filter(l => 
        (String(l.message || '').toLowerCase().includes(s)) ||
        (String(l.source || '').toLowerCase().includes(s)) ||
        (String(l.event_id || '').includes(s))
      );
    }

    const countElem = document.getElementById('sysLogFilteredCount');
    if (countElem) countElem.textContent = `${filtered.length} shown (of ${this.systemLogs.length})`;

    if (filtered.length === 0) {
      const emptyHtml = `<tr><td colspan="6" class="text-center py-10 text-slate-500 font-mono text-xs">No matching system events found.</td></tr>`;
      if (tbody) tbody.innerHTML = emptyHtml;
      if (splitTbody) splitTbody.innerHTML = emptyHtml;
      return;
    }

    const rowsHtml = filtered.map(log => {
      const lvl = (log.level || 'INFO').toUpperCase();
      let badgeClass = "bg-sky-500/10 text-sky-400 border border-sky-500/30";
      if (lvl === 'ERROR' || lvl === 'CRITICAL') {
        badgeClass = "bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse";
      } else if (lvl === 'WARNING') {
        badgeClass = "bg-amber-500/20 text-amber-300 border border-amber-500/40";
      } else if (lvl === 'AUDIT') {
        badgeClass = "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40";
      }

      const msgStr = String(log.message || '');
      const srcStr = String(log.source || 'system');
      const safeTitle = msgStr.replace(/"/g, '&quot;');

      return `
        <tr class="hover:bg-slate-800/40 transition cursor-pointer border-b border-slate-800/40 text-xs font-mono" data-sysid="${log.id}">
          <td class="py-2.5 px-3 text-slate-400 whitespace-nowrap">${log.timestamp || 'N/A'}</td>
          <td class="py-2.5 px-3">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${badgeClass}">${lvl}</span>
          </td>
          <td class="py-2.5 px-3 font-semibold text-slate-200 truncate max-w-[160px]" title="${srcStr}">${srcStr}</td>
          <td class="py-2.5 px-3 text-cyan-400">${log.event_id || 1000}</td>
          <td class="py-2.5 px-3 text-slate-300 truncate max-w-[420px]" title="${safeTitle}">${msgStr}</td>
          <td class="py-2.5 px-3 text-right">
            <button class="view-sys-detail-btn px-2 py-1 rounded bg-slate-800 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 border border-slate-700 text-[11px] transition" data-sysid="${log.id}">
              Inspect
            </button>
          </td>
        </tr>
      `;
    }).join('');

    if (tbody) {
      tbody.innerHTML = rowsHtml;
      if (this.systemLiveTail && tbody.parentElement) {
        tbody.parentElement.scrollTop = 0;
      }
    }

    if (splitTbody) {
      splitTbody.innerHTML = rowsHtml;
    }

    // Attach click events for inspect
    document.querySelectorAll('.view-sys-detail-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const id = btn.getAttribute('data-sysid');
        const item = this.systemLogs.find(l => l.id === id);
        if (item) this.showEventDetailModal("OS System Event", item);
      });
    });
  }

  // =========================================================================
  // 2. SECURITY LOGS & THREAT AUDIT
  // =========================================================================
  bindSecurityLogEvents() {
    // Category pills
    document.querySelectorAll('.sec-cat-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.sec-cat-pill').forEach(b => {
          b.className = "sec-cat-pill px-2.5 py-1 rounded text-xs font-mono transition border border-transparent text-slate-400 hover:text-slate-200";
        });
        btn.className = "sec-cat-pill px-2.5 py-1 rounded text-xs font-mono transition border border-cyan-500/50 bg-cyan-500/20 text-cyan-300 font-bold";
        this.securityFilterCategory = btn.getAttribute('data-cat');
        this.fetchSecurityLogs(true);
      });
    });

    // Severity pills
    document.querySelectorAll('.sec-sev-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.sec-sev-pill').forEach(b => {
          b.className = "sec-sev-pill px-2 py-0.5 rounded text-[11px] font-mono transition border border-transparent text-slate-400 hover:text-slate-200";
        });
        btn.className = "sec-sev-pill px-2 py-0.5 rounded text-[11px] font-mono transition border border-cyan-500/50 bg-cyan-500/20 text-cyan-300 font-bold";
        this.securityFilterSeverity = btn.getAttribute('data-sev');
        this.fetchSecurityLogs(true);
      });
    });

    // Search
    const searchInput = document.getElementById('secLogSearch');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.securityFilterSearch = e.target.value.trim();
        this.renderSecurityLogs();
      });
    }

    // Refresh
    const refreshBtn = document.getElementById('secLogRefreshBtn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        this.fetchSecurityLogs(true);
        window.AegisUI.showToast("Security logs refreshed", "info");
      });
    }

    // Scan Logs for Threats Trigger
    const scanBtn = document.getElementById('scanThreatsBtn');
    if (scanBtn) {
      scanBtn.addEventListener('click', () => this.scanLogsForThreats());
    }
  }

  async fetchSecurityLogs(showToast = false) {
    try {
      const url = new URL('/api/logs/security', window.location.origin);
      url.searchParams.set('limit', '120');
      if (this.securityFilterCategory !== 'ALL') url.searchParams.set('category', this.securityFilterCategory);
      if (this.securityFilterSeverity !== 'ALL') url.searchParams.set('severity', this.securityFilterSeverity);
      if (this.securityFilterSearch) url.searchParams.set('search', this.securityFilterSearch);

      const resp = await fetch(url.toString());
      if (resp.ok) {
        const data = await resp.json();
        this.securityLogs = data.logs || [];
        this.renderSecurityLogs();
        if (showToast) window.AegisUI.showToast(`Loaded ${this.securityLogs.length} security events`, "info");
      }
    } catch (e) {
      console.warn("Failed to fetch security logs:", e);
    }
  }

  renderSecurityLogs() {
    const tbody = document.getElementById('securityLogsTableBody');
    if (!tbody) return;

    let filtered = this.securityLogs;
    if (this.securityFilterSearch) {
      const s = this.securityFilterSearch.toLowerCase();
      filtered = filtered.filter(l => 
        (l.title && l.title.toLowerCase().includes(s)) ||
        (l.description && l.description.toLowerCase().includes(s)) ||
        (l.source_ip && l.source_ip.toLowerCase().includes(s)) ||
        (l.user && l.user.toLowerCase().includes(s))
      );
    }

    const countElem = document.getElementById('secLogFilteredCount');
    if (countElem) countElem.textContent = `${filtered.length} shown (of ${this.securityLogs.length})`;

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center py-10 text-slate-500 font-mono text-xs">No matching security incident events found.</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(log => {
      const sev = (log.severity || 'INFO').toUpperCase();
      let sevClass = "bg-sky-500/10 text-sky-400 border border-sky-500/30";
      if (sev === 'CRITICAL') {
        sevClass = "bg-rose-500/25 text-rose-300 border border-rose-500/50 cyber-glow-rose";
      } else if (sev === 'HIGH') {
        sevClass = "bg-rose-500/20 text-rose-400 border border-rose-500/40";
      } else if (sev === 'MEDIUM') {
        sevClass = "bg-amber-500/20 text-amber-300 border border-amber-500/40";
      }

      const ipStr = log.source_ip || '127.0.0.1';
      const isRemote = (ipStr !== '127.0.0.1' && ipStr !== 'LOCAL' && !ipStr.startsWith('192.168.') && !ipStr.startsWith('10.'));

      return `
        <tr class="hover:bg-slate-800/40 transition border-b border-slate-800/40 text-xs font-mono">
          <td class="py-2.5 px-3 text-slate-400 whitespace-nowrap">${log.timestamp ? log.timestamp.replace('T', ' ').slice(0, 19) : 'N/A'}</td>
          <td class="py-2.5 px-3">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${sevClass}">${sev}</span>
          </td>
          <td class="py-2.5 px-3">
            <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">${log.category || 'AUDIT'}</span>
          </td>
          <td class="py-2.5 px-3 font-semibold text-slate-200">
            <div class="truncate max-w-[220px]" title="${log.title}">${log.title}</div>
            <div class="text-[11px] text-slate-400 truncate max-w-[280px]" title="${log.description}">${log.description}</div>
          </td>
          <td class="py-2.5 px-3 text-cyan-300 font-mono">${log.user || 'SYSTEM'}</td>
          <td class="py-2.5 px-3">
            <div class="flex items-center space-x-1">
              <span class="font-mono text-slate-300">${ipStr}</span>
              ${isRemote ? `<button class="quick-block-btn text-[10px] px-1.5 py-0.5 rounded bg-rose-500/20 hover:bg-rose-500/40 text-rose-300 border border-rose-500/40 transition" data-ip="${ipStr}" title="Block IP">Block</button>` : ''}
            </div>
          </td>
          <td class="py-2.5 px-3 text-right whitespace-nowrap">
            <button class="view-sec-detail-btn px-2 py-1 rounded bg-slate-800 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 border border-slate-700 text-[11px] transition" data-secid="${log.id}">
              Inspect
            </button>
          </td>
        </tr>
      `;
    }).join('');

    // Attach inspect buttons
    document.querySelectorAll('.view-sec-detail-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-secid');
        const item = this.securityLogs.find(l => l.id === id);
        if (item) this.showEventDetailModal("Security Incident Dossier", item);
      });
    });

    // Attach quick block buttons
    document.querySelectorAll('.quick-block-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const ip = btn.getAttribute('data-ip');
        if (confirm(`Enforce permanent OS firewall drop against IP ${ip}?`)) {
          await this.app.inspector.handleBlockIP(ip, "SOC Incident Response Block");
          this.fetchSecurityLogs(true);
        }
      });
    });
  }

  // =========================================================================
  // 3. LOGIN ATTEMPTS & ACTIVE SESSIONS
  // =========================================================================
  bindLoginEvents() {
    // Status filter
    document.querySelectorAll('.login-status-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.login-status-pill').forEach(b => {
          b.className = "login-status-pill px-2.5 py-1 rounded text-xs font-mono transition border border-transparent text-slate-400 hover:text-slate-200";
        });
        btn.className = "login-status-pill px-2.5 py-1 rounded text-xs font-mono transition border border-cyan-500/50 bg-cyan-500/20 text-cyan-300 font-bold";
        this.loginFilterStatus = btn.getAttribute('data-status');
        this.fetchLoginAttempts(true);
      });
    });

    // Search
    const searchInput = document.getElementById('loginSearch');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.loginFilterSearch = e.target.value.trim();
        this.renderLoginAttempts();
      });
    }

    // Refresh
    const refreshBtn = document.getElementById('loginRefreshBtn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        this.fetchLoginAttempts(true);
        window.AegisUI.showToast("Authentication logs refreshed", "info");
      });
    }

    // Auth Scan Threats Trigger
    const authScanBtn = document.getElementById('authScanThreatsBtn');
    if (authScanBtn) {
      authScanBtn.addEventListener('click', () => this.scanLogsForThreats());
    }
  }

  async fetchLoginAttempts(showToast = false) {
    try {
      const url = new URL('/api/logs/logins', window.location.origin);
      url.searchParams.set('limit', '120');
      if (this.loginFilterStatus !== 'ALL') url.searchParams.set('status', this.loginFilterStatus);
      if (this.loginFilterSearch) url.searchParams.set('search', this.loginFilterSearch);

      const resp = await fetch(url.toString());
      if (resp.ok) {
        const data = await resp.json();
        this.loginAttempts = data.attempts || [];
        this.renderLoginAttempts();
      }

      // Also fetch active sessions
      const sessResp = await fetch('/api/logs/sessions');
      if (sessResp.ok) {
        const sdata = await sessResp.json();
        this.activeSessions = sdata.sessions || [];
        this.renderActiveSessions();
      }

      this.fetchStats();
      if (showToast) window.AegisUI.showToast(`Loaded ${this.loginAttempts.length} authentication records`, "info");
    } catch (e) {
      console.warn("Failed to fetch login attempts:", e);
    }
  }

  renderActiveSessions() {
    const container = document.getElementById('activeSessionsList');
    if (!container) return;

    if (this.activeSessions.length === 0) {
      container.innerHTML = `<div class="text-slate-500 font-mono text-xs py-2">No active interactive sessions reported.</div>`;
      return;
    }

    container.innerHTML = this.activeSessions.map(sess => `
      <div class="flex items-center justify-between p-2 rounded bg-slate-900/80 border border-slate-800 text-xs font-mono">
        <div class="flex items-center space-x-2">
          <div class="w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_6px_#10b981]"></div>
          <span class="font-bold text-white">${sess.username}</span>
          <span class="text-slate-400 text-[10px] px-1.5 py-0.5 rounded bg-slate-800">${sess.terminal}</span>
        </div>
        <div class="text-slate-400 text-[11px]">
          <span>Logged in: ${sess.started}</span>
        </div>
      </div>
    `).join('');
  }

  renderLoginAttempts() {
    const tbody = document.getElementById('loginAttemptsTableBody');
    if (!tbody) return;

    let filtered = this.loginAttempts;
    if (this.loginFilterSearch) {
      const s = this.loginFilterSearch.toLowerCase();
      filtered = filtered.filter(a => 
        (a.username && a.username.toLowerCase().includes(s)) ||
        (a.source_ip && a.source_ip.toLowerCase().includes(s)) ||
        (a.logon_type && a.logon_type.toLowerCase().includes(s)) ||
        (a.failure_reason && a.failure_reason.toLowerCase().includes(s))
      );
    }

    const countElem = document.getElementById('loginFilteredCount');
    if (countElem) countElem.textContent = `${filtered.length} shown (of ${this.loginAttempts.length})`;

    if (filtered.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center py-10 text-slate-500 font-mono text-xs">No matching login attempts recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = filtered.map(item => {
      const st = (item.status || 'INFO').toUpperCase();
      let stBadge = "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40";
      if (st === 'FAILED') {
        stBadge = "bg-rose-500/25 text-rose-300 border border-rose-500/50 animate-pulse font-bold";
      } else if (st === 'LOGOFF' || st === 'DISCONNECTED') {
        stBadge = "bg-slate-800 text-slate-400 border border-slate-700";
      }

      const ipStr = item.source_ip || 'LOCAL';
      const isRemote = (ipStr !== 'LOCAL' && ipStr !== '127.0.0.1' && !ipStr.startsWith('192.168.'));
      const geo = item.geo || {};
      const flagStr = geo.country_code ? `[${geo.country_code}] ${geo.city || ''}` : '';

      return `
        <tr class="hover:bg-slate-800/40 transition border-b border-slate-800/40 text-xs font-mono">
          <td class="py-2.5 px-3">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${stBadge}">${st}</span>
          </td>
          <td class="py-2.5 px-3 text-slate-400 whitespace-nowrap">${item.timestamp ? item.timestamp.replace('T', ' ').slice(0, 19) : 'N/A'}</td>
          <td class="py-2.5 px-3 font-bold text-white">${item.username}</td>
          <td class="py-2.5 px-3 text-slate-300 truncate max-w-[150px]">${item.logon_type || 'Interactive'}</td>
          <td class="py-2.5 px-3">
            <div class="flex items-center space-x-1.5">
              <span class="text-cyan-300 font-mono">${ipStr}</span>
              ${flagStr ? `<span class="text-[10px] text-slate-400">${flagStr}</span>` : ''}
            </div>
          </td>
          <td class="py-2.5 px-3 text-slate-300 truncate max-w-[280px]" title="${item.failure_reason}">${item.failure_reason}</td>
          <td class="py-2.5 px-3 text-right whitespace-nowrap">
            <div class="flex items-center justify-end space-x-1">
              ${isRemote ? `
                <button class="quick-block-btn text-[10px] px-2 py-1 rounded bg-rose-500/20 hover:bg-rose-500/35 text-rose-300 border border-rose-500/40 transition" data-ip="${ipStr}">
                  Block IP
                </button>
              ` : ''}
              <button class="view-login-detail-btn px-2 py-1 rounded bg-slate-800 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 border border-slate-700 text-[11px] transition" data-authid="${item.id}">
                Inspect
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    // Attach inspect buttons
    document.querySelectorAll('.view-login-detail-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.getAttribute('data-authid');
        const item = this.loginAttempts.find(a => a.id === id);
        if (item) this.showEventDetailModal("Authentication Attempt Dossier", item);
      });
    });

    // Attach quick block buttons
    document.querySelectorAll('.quick-block-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const ip = btn.getAttribute('data-ip');
        if (confirm(`Block ${ip} immediately via native OS firewall?`)) {
          await this.app.inspector.handleBlockIP(ip, "Failed Authentication Incident Block");
          this.fetchLoginAttempts(true);
        }
      });
    });
  }

  // =========================================================================
  // STATS & KPI UPDATE
  // =========================================================================
  async fetchStats() {
    try {
      const resp = await fetch('/api/logs/stats');
      if (resp.ok) {
        const stats = await resp.json();
        this.updateStatsDisplay(stats);
      }
    } catch (e) {
      console.warn("Failed to fetch log stats:", e);
    }
  }

  updateStatsDisplay(stats) {
    this.authStats = stats;

    // Header Badges
    const badgeSysErrors = document.getElementById('kpiSysErrors');
    if (badgeSysErrors) badgeSysErrors.textContent = `${stats.system_errors || 0} err / ${stats.system_warnings || 0} warn`;

    const badgeSecIncidents = document.getElementById('kpiSecIncidents');
    if (badgeSecIncidents) badgeSecIncidents.textContent = stats.security_incidents || 0;

    const badgeLogins = document.getElementById('kpiLoginsTotal');
    if (badgeLogins) badgeLogins.textContent = `${stats.total_logins_24h || 0} (${stats.failed_logins_24h || 0} failed)`;

    // Top Header Nav Badges
    const navSys = document.getElementById('navHeaderSysCount');
    if (navSys) navSys.textContent = (stats.system_errors || 0) + (stats.system_warnings || 0);

    const navSec = document.getElementById('navHeaderSecCount');
    if (navSec) navSec.textContent = stats.security_incidents || 0;

    const navLogins = document.getElementById('navHeaderLoginsCount');
    if (navLogins) navLogins.textContent = stats.total_logins_24h || 0;

    // Brute-force Alert Banner
    const bruteBanner = document.getElementById('bruteForceAlertBanner');
    if (bruteBanner) {
      if (stats.brute_force_risk === 'HIGH_ALERT') {
        bruteBanner.className = "cyber-card rounded-lg p-3 bg-rose-950/70 border border-rose-500 flex items-center justify-between text-rose-200 cyber-glow-rose";
        bruteBanner.classList.remove('hidden');
        document.getElementById('bruteForceRiskText').textContent = "HIGH ALERT: Brute-Force Authentication Anomaly Detected!";
      } else if (stats.brute_force_risk === 'ELEVATED') {
        bruteBanner.className = "cyber-card rounded-lg p-3 bg-amber-950/60 border border-amber-500/80 flex items-center justify-between text-amber-200";
        bruteBanner.classList.remove('hidden');
        document.getElementById('bruteForceRiskText').textContent = "ELEVATED: Failed Authentication Attempts Detected";
      } else {
        bruteBanner.classList.add('hidden');
      }
    }
  }

  // =========================================================================
  // MODALS & EVENT INSPECTOR
  // =========================================================================
  bindModalEvents() {
    // Event Detail Modal Close
    const closeDetailBtn = document.getElementById('closeEventDetailBtn');
    if (closeDetailBtn) {
      closeDetailBtn.addEventListener('click', () => {
        document.getElementById('eventDetailModal').classList.add('hidden');
      });
    }

    // Copy Event JSON
    const copyDetailBtn = document.getElementById('copyEventDetailBtn');
    if (copyDetailBtn) {
      copyDetailBtn.addEventListener('click', () => {
        if (this.selectedEvent) {
          navigator.clipboard.writeText(JSON.stringify(this.selectedEvent, null, 2));
          window.AegisUI.showToast("Event payload copied to clipboard", "success");
        }
      });
    }

  }

  async scanLogsForThreats() {
    try {
      if (window.AegisUI) {
        window.AegisUI.showToast("Analyzing system logs for threats...", "info");
      }
      const resp = await fetch('/api/logs/scan-threats', { method: 'POST' });
      if (resp.ok) {
        const data = await resp.json();
        const found = data.threats_discovered_now || 0;
        const total = data.total_active_threats || 0;
        if (found > 0) {
          if (window.AegisUI) {
            window.AegisUI.showToast(`🚨 Detected ${found} new threat(s) in system logs! Total: ${total}`, "warning");
          }
        } else {
          if (window.AegisUI) {
            window.AegisUI.showToast(`✓ Scan completed. ${data.scanned_system_events || 0} events analyzed. No new threats.`, "success");
          }
        }
        this.fetchSecurityLogs(false);
        this.fetchLoginAttempts(false);
        this.fetchStats();
      }
    } catch (e) {
      console.warn("Threat scan failed:", e);
      if (window.AegisUI) {
        window.AegisUI.showToast("Log threat scan error: " + (e.message || e), "error");
      }
    }
  }

  showEventDetailModal(title, eventObj) {
    this.selectedEvent = eventObj;
    document.getElementById('eventDetailModalTitle').textContent = title;
    document.getElementById('eventDetailTimestamp').textContent = eventObj.timestamp || 'N/A';
    document.getElementById('eventDetailSource').textContent = eventObj.source || eventObj.category || 'System';
    document.getElementById('eventDetailRaw').textContent = JSON.stringify(eventObj, null, 2);
    document.getElementById('eventDetailModal').classList.remove('hidden');
  }

  exportLogsAsJson(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    window.AegisUI.showToast(`Exported ${data.length} records to ${filename}`, "success");
  }
}

window.AegisLogs = AegisLogsManager;
