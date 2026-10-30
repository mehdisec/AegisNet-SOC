/**
 * AegisNet SOC Dashboard Controller & Real-Time WebSocket Orchestrator
 */

class CyberAudio {
  constructor() {
    this.enabled = false;
    this.ctx = null;
  }

  init() {
    if (!this.ctx) {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext) {
        this.ctx = new AudioContext();
      }
    }
  }

  toggle() {
    this.enabled = !this.enabled;
    if (this.enabled) this.init();
    return this.enabled;
  }

  play(type = 'ping') {
    if (!this.enabled) return;
    this.init();
    if (!this.ctx) return;

    try {
      if (this.ctx.state === 'suspended') {
        this.ctx.resume();
      }

      const now = this.ctx.currentTime;
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();

      osc.connect(gain);
      gain.connect(this.ctx.destination);

      if (type === 'ping') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(880, now);
        osc.frequency.exponentialRampToValueAtTime(1320, now + 0.08);
        gain.gain.setValueAtTime(0.04, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.08);
        osc.start(now);
        osc.stop(now + 0.08);
      } else if (type === 'kill') {
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(600, now);
        osc.frequency.exponentialRampToValueAtTime(150, now + 0.25);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
        osc.start(now);
        osc.stop(now + 0.25);
      } else if (type === 'block') {
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(200, now);
        osc.frequency.exponentialRampToValueAtTime(50, now + 0.3);
        gain.gain.setValueAtTime(0.12, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
        osc.start(now);
        osc.stop(now + 0.3);
      }
    } catch (e) {
      // Ignore audio failures
    }
  }
}

class AegisApp {
  constructor() {
    this.ws = null;
    this.isPaused = false;
    this.audio = new CyberAudio();
    this.map = null;
    this.inspector = null;

    this.allConnections = [];
    this.filteredConnections = [];
    this.searchQuery = '';
    this.protocolFilter = 'ALL';
    this.hostInfo = null;

    this.init();
  }

  async init() {
    this.initUI();
    this.initMapAndInspector();
    if (window.AegisLogs) {
      this.logs = new window.AegisLogs(this);
    }
    await this.fetchSystemStatus();
    this.initWebSocket();
  }

  initUI() {
    // Sound FX Toggle
    const soundBtn = document.getElementById('toggleSoundBtn');
    if (soundBtn) {
      soundBtn.addEventListener('click', () => {
        const isMuted = !this.audio.toggle();
        soundBtn.innerHTML = isMuted 
          ? `<i data-lucide="volume-x" class="w-4 h-4 text-slate-400"></i>` 
          : `<i data-lucide="volume-2" class="w-4 h-4 text-cyan-400"></i>`;
        soundBtn.classList.toggle('border-cyan-500', !isMuted);
        if (window.lucide) window.lucide.createIcons();
        window.AegisUI.showToast(`Audio FX ${isMuted ? 'Muted' : 'Enabled'}`, 'info');
      });
    }

    // Pause/Resume Stream Toggle
    const pauseBtn = document.getElementById('togglePauseBtn');
    if (pauseBtn) {
      pauseBtn.addEventListener('click', () => {
        this.isPaused = !this.isPaused;
        pauseBtn.innerHTML = this.isPaused
          ? `<i data-lucide="play" class="w-4 h-4 text-amber-400 mr-1.5"></i> Stream Paused`
          : `<i data-lucide="pause" class="w-4 h-4 text-cyan-400 mr-1.5"></i> Live Stream`;
        pauseBtn.classList.toggle('border-amber-500', this.isPaused);
        pauseBtn.classList.toggle('text-amber-400', this.isPaused);
        if (window.lucide) window.lucide.createIcons();
      });
    }

    // Rules Manager Modal Open/Close
    const rulesBtn = document.getElementById('openRulesModalBtn');
    const rulesModal = document.getElementById('firewallRulesModal');
    const closeRulesBtn = document.getElementById('closeRulesModalBtn');

    if (rulesBtn && rulesModal) {
      rulesBtn.addEventListener('click', () => {
        this.loadFirewallRules();
        rulesModal.classList.remove('hidden');
      });
    }
    if (closeRulesBtn && rulesModal) {
      closeRulesBtn.addEventListener('click', () => rulesModal.classList.add('hidden'));
    }

    // Reports & SIEM Export Modal Open/Close
    const repBtn = document.getElementById('openReportsModalBtn');
    const repModal = document.getElementById('reportsExportModal');
    const closeRepBtn = document.getElementById('closeReportsModalBtn');
    if (repBtn && repModal) {
      repBtn.addEventListener('click', () => repModal.classList.remove('hidden'));
    }
    if (closeRepBtn && repModal) {
      closeRepBtn.addEventListener('click', () => repModal.classList.add('hidden'));
    }

    // Threat Intel Modal Open/Close & Lookup
    const intelBtn = document.getElementById('openIntelModalBtn');
    const intelModal = document.getElementById('threatIntelModal');
    const closeIntelBtn = document.getElementById('closeIntelModalBtn');
    const intelQueryBtn = document.getElementById('intelQueryBtn');
    const intelQueryInput = document.getElementById('intelQueryIPInput');

    if (intelBtn && intelModal) {
      intelBtn.addEventListener('click', async () => {
        intelModal.classList.remove('hidden');
        try {
          const statsRes = await fetch('/api/intel/stats');
          const statsData = await statsRes.json();
          const torEl = document.getElementById('intelTorCount');
          const cacheEl = document.getElementById('intelCacheCount');
          if (torEl) torEl.textContent = `${statsData.tor_nodes_loaded || 0} Exit Relays`;
          if (cacheEl) cacheEl.textContent = `${statsData.cache_size || 0} Indexed`;
        } catch (e) {
          console.debug("Failed to load intel stats:", e);
        }
      });
    }
    if (closeIntelBtn && intelModal) {
      closeIntelBtn.addEventListener('click', () => intelModal.classList.add('hidden'));
    }

    const runIntelQuery = async () => {
      const ip = (intelQueryInput.value || '').trim();
      if (!ip) return;
      try {
        const res = await fetch(`/api/intel/lookup?ip=${encodeURIComponent(ip)}`);
        const data = await res.json();
        
        const verdictEl = document.getElementById('intelVerdict');
        const scoreEl = document.getElementById('intelScore');
        const catEl = document.getElementById('intelCategory');
        const confEl = document.getElementById('intelConfidence');
        const indEl = document.getElementById('intelIndicators');

        if (verdictEl) {
          verdictEl.textContent = data.verdict;
          let vCol = 'text-emerald-400';
          if (data.verdict === 'MALICIOUS') vCol = 'text-rose-400 font-bold';
          else if (data.verdict === 'SUSPICIOUS') vCol = 'text-amber-400 font-bold';
          verdictEl.className = `font-bold text-sm ${vCol}`;
        }
        if (scoreEl) {
          scoreEl.textContent = `${data.score} / 100 (${data.level} RISK)`;
          scoreEl.style.color = data.score >= 80 ? '#f43f5e' : (data.score >= 50 ? '#f59e0b' : '#10b981');
        }
        if (catEl) catEl.textContent = data.category || 'N/A';
        if (confEl) confEl.textContent = `${data.confidence || 90}% Confidence`;
        if (indEl) {
          indEl.innerHTML = (data.indicators || []).map(ind => 
            `<div class="py-0.5 text-slate-300 font-mono">• ${ind}</div>`
          ).join('') || 'No threat indicators matched.';
        }
      } catch (err) {
        window.AegisUI.showToast("Intel lookup failed: " + err, "error");
      }
    };

    if (intelQueryBtn) intelQueryBtn.addEventListener('click', runIntelQuery);
    if (intelQueryInput) intelQueryInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') runIntelQuery();
    });

    // Search Input
    const searchInput = document.getElementById('tableSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase().trim();
        this.applyFilterAndRender();
      });
    }

    // Synchronized Protocol Filters (Table & Map)
    const updateProtocolFilterUI = (proto) => {
      this.protocolFilter = proto;

      // Update Table Pills
      document.querySelectorAll('.proto-filter-pill').forEach(b => {
        const isActive = b.dataset.protocol === proto;
        b.classList.toggle('bg-cyan-500/20', isActive);
        b.classList.toggle('text-cyan-300', isActive);
        b.classList.toggle('border-cyan-500/40', isActive);
        b.classList.toggle('text-slate-400', !isActive);
        b.classList.toggle('border-transparent', !isActive);
      });

      // Update Map Pills
      document.querySelectorAll('.map-proto-pill').forEach(b => {
        const isActive = b.dataset.proto === proto;
        b.classList.toggle('bg-cyan-500/20', isActive);
        b.classList.toggle('text-cyan-300', isActive);
        b.classList.toggle('border-cyan-500/50', isActive);
        b.classList.toggle('font-bold', isActive);
        b.classList.toggle('border-transparent', !isActive);
      });

      // Update Map filter
      if (this.map) {
        this.map.setProtocolFilter(proto);
      }

      this.applyFilterAndRender();
      if (window.AegisUI) {
        window.AegisUI.showToast(`Protocol Filter: ${proto}`, 'info');
      }
    };

    document.querySelectorAll('.proto-filter-pill').forEach(btn => {
      btn.addEventListener('click', () => updateProtocolFilterUI(btn.dataset.protocol));
    });

    document.querySelectorAll('.map-proto-pill').forEach(btn => {
      btn.addEventListener('click', () => updateProtocolFilterUI(btn.dataset.proto));
    });

    // Toggle Basemap Mode Button
    const toggleMapBtn = document.getElementById('toggleMapModeBtn');
    const mapLabel = document.getElementById('mapModeLabel');
    if (toggleMapBtn && mapLabel) {
      toggleMapBtn.addEventListener('click', () => {
        if (this.map) {
          const modeName = this.map.toggleBasemapMode();
          mapLabel.textContent = modeName;
          window.AegisUI.showToast(`Basemap switched to: ${modeName}`, 'info');
        }
      });
    }

    // Reset Map View Button
    const resetMapBtn = document.getElementById('resetMapBtn');
    if (resetMapBtn) {
      resetMapBtn.addEventListener('click', () => {
        if (this.map && this.hostInfo && this.hostInfo.host_location) {
          const loc = this.hostInfo.host_location;
          this.map.flyToCoordinates(loc.lat, loc.lon, 3.5);
        } else if (this.map) {
          this.map.flyToCoordinates(25, 10, 2.3);
        }
      });
    }

    // Intro Animation, Creator Modal & Desktop Integration
    this.initIntroAnimation();
    this.initAboutModal();
    this.initDesktopMode();
  }

  initIntroAnimation() {
    const splash = document.getElementById('aegisIntroSplash');
    if (!splash) return;

    const fill = document.getElementById('introProgressFill');
    const s2 = document.getElementById('bootStep2');
    const s3 = document.getElementById('bootStep3');
    const s4 = document.getElementById('bootStep4');
    const skipBtn = document.getElementById('skipIntroBtn');

    let dismissed = false;
    const dismissSplash = () => {
      if (dismissed) return;
      dismissed = true;
      splash.classList.add('hidden-splash');
      setTimeout(() => {
        try { splash.remove(); } catch(e) {}
      }, 750);
    };

    if (skipBtn) {
      skipBtn.addEventListener('click', dismissSplash);
    }

    setTimeout(() => { if (fill) fill.style.width = '35%'; if (s2) s2.classList.remove('opacity-0'); }, 250);
    setTimeout(() => { if (fill) fill.style.width = '70%'; if (s3) s3.classList.remove('opacity-0'); }, 600);
    setTimeout(() => { if (fill) fill.style.width = '90%'; if (s4) s4.classList.remove('opacity-0'); }, 950);
    setTimeout(() => { if (fill) fill.style.width = '100%'; }, 1250);
    setTimeout(dismissSplash, 1600);
  }

  initAboutModal() {
    const openBtn = document.getElementById('openAboutModalBtn');
    const modal = document.getElementById('creatorAboutModal');
    const closeBtn = document.getElementById('closeAboutModalBtn');
    if (!modal) return;

    if (openBtn) {
      openBtn.addEventListener('click', () => {
        modal.classList.remove('hidden');
        if (window.lucide) window.lucide.createIcons();
      });
    }

    if (closeBtn) {
      closeBtn.addEventListener('click', () => modal.classList.add('hidden'));
    }

    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.classList.add('hidden');
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
        modal.classList.add('hidden');
      }
    });
  }

  initDesktopMode() {
    // Check if pywebview is injected or desktop app mode active
    const checkDesktop = () => {
      const isDesktop = window.pywebview !== undefined || navigator.userAgent.includes('AegisNetDesktop');
      const exitBtn = document.getElementById('desktopExitBtn');
      if (isDesktop && exitBtn) {
        exitBtn.classList.remove('hidden');
      }
    };

    checkDesktop();
    window.addEventListener('pywebviewready', checkDesktop);

    window.triggerAppShutdown = () => {
      const exitOverlay = document.getElementById('aegisExitOverlay');
      if (exitOverlay) exitOverlay.classList.add('active');
      if (this.audio && this.audio.enabled) {
        this.audio.play('kill');
      }
    };

    const exitBtn = document.getElementById('desktopExitBtn');
    if (exitBtn) {
      exitBtn.addEventListener('click', () => {
        window.triggerAppShutdown();
        setTimeout(() => {
          if (window.pywebview && window.pywebview.api && window.pywebview.api.exit_app) {
            window.pywebview.api.exit_app();
          } else {
            window.close();
          }
        }, 900);
      });
    }
  }

  initMapAndInspector() {
    this.map = new window.AegisMap('worldMap', {
      onSelectIP: (ip, conn) => {
        this.inspector.inspect(ip, conn);
      }
    });

    this.inspector = new window.IPInspector({
      playAudio: (type) => this.audio.play(type),
      onFlyToMap: (lat, lon, zoom) => {
        this.map.flyToCoordinates(lat, lon, zoom);
      },
      onActionSuccess: () => {
        // Trigger immediate telemetry refresh
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
          this.ws.send(JSON.stringify({ action: "REFRESH" }));
        }
      }
    });
  }

  async fetchSystemStatus() {
    try {
      const resp = await fetch('/api/system/status');
      const data = await resp.json();
      this.hostInfo = data;

      // Update System Badges in Header
      document.getElementById('sysHostname').textContent = data.hostname || 'Host';
      
      const osBadge = document.getElementById('sysOSBadge');
      if (osBadge) {
        osBadge.innerHTML = `<span class="inline-block w-2 h-2 rounded-full ${data.os === 'Windows' ? 'bg-sky-400' : 'bg-emerald-400'} mr-1.5"></span> ${data.os} (${data.architecture})`;
      }

      const adminBadge = document.getElementById('sysAdminBadge');
      if (adminBadge) {
        if (data.is_admin) {
          adminBadge.innerHTML = `<i data-lucide="shield-check" class="w-3.5 h-3.5 text-emerald-400 mr-1"></i> <span class="text-emerald-400">ELEVATED PRIVILEGES</span>`;
          adminBadge.className = "flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-emerald-500/10 border border-emerald-500/30";
        } else {
          adminBadge.innerHTML = `<i data-lucide="shield-alert" class="w-3.5 h-3.5 text-amber-400 mr-1"></i> <span class="text-amber-400">RESTRICTED USER</span>`;
          adminBadge.className = "flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-amber-500/10 border border-amber-500/30";
          adminBadge.title = "Firewall manipulation commands may require launching as Administrator / Root.";
        }
      }

      if (data.host_location) {
        this.map.setHostLocation(data.host_location);
      }

      if (window.lucide) window.lucide.createIcons();
    } catch (e) {
      console.warn("Could not fetch system status:", e);
    }
  }

  initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live`;
    const statusLed = document.getElementById('wsStatusLed');
    const statusText = document.getElementById('wsStatusText');

    this.ws = new WebSocket(wsUrl);

    this.ws.onopen = () => {
      if (statusLed) {
        statusLed.className = "w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#10b981]";
      }
      if (statusText) statusText.textContent = "STREAM ACTIVE";
      window.AegisUI.showToast("Real-time telemetry stream connected", "success");
    };

    this.ws.onmessage = (event) => {
      if (this.isPaused) return;

      try {
        const msg = JSON.parse(event.data);
        if (msg.type === 'TELEMETRY_UPDATE' || msg.type === 'INITIAL_STATE') {
          this.handleTelemetryUpdate(msg.data);
          if (msg.log_stats && this.logs) {
            this.logs.updateStatsDisplay(msg.log_stats);
          }
        } else if (msg.type === 'SYSTEM_LOGS_DATA' && this.logs) {
          this.logs.systemLogs = msg.logs || [];
          this.logs.renderSystemLogs();
        } else if (msg.type === 'SECURITY_LOGS_DATA' && this.logs) {
          this.logs.securityLogs = msg.logs || [];
          this.logs.renderSecurityLogs();
        } else if (msg.type === 'LOGIN_LOGS_DATA' && this.logs) {
          this.logs.loginAttempts = msg.logins || [];
          this.logs.activeSessions = msg.sessions || [];
          this.logs.renderLoginAttempts();
          this.logs.renderActiveSessions();
          if (msg.stats) this.logs.updateStatsDisplay(msg.stats);
        }
      } catch (err) {
        console.error("Failed to parse WS message:", err);
      }
    };

    this.ws.onclose = () => {
      if (statusLed) {
        statusLed.className = "w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_8px_#f43f5e] animate-ping";
      }
      if (statusText) statusText.textContent = "RECONNECTING...";
      setTimeout(() => this.initWebSocket(), 2500);
    };

    this.ws.onerror = (err) => {
      console.warn("WebSocket error:", err);
    };
  }

  handleTelemetryUpdate(data) {
    if (!data) return;

    this.allConnections = data.connections || [];
    
    // Update Header Metric Counters
    document.getElementById('metricTotalConns').textContent = data.total_connections || 0;
    document.getElementById('metricEstablished').textContent = data.established_count || 0;
    document.getElementById('metricActiveRemote').textContent = data.active_remote_count || 0;

    // Bandwidth Counters
    if (data.bandwidth) {
      const bw = data.bandwidth;
      document.getElementById('metricTxRate').textContent = `${bw.tx_kbps} KB/s`;
      document.getElementById('metricRxRate').textContent = `${bw.rx_kbps} KB/s`;
      document.getElementById('metricTxTotal').textContent = `${bw.total_sent_mb} MB`;
      document.getElementById('metricRxTotal').textContent = `${bw.total_recv_mb} MB`;
    }

    // Update Telemetry Side Panels
    if (data.telemetry) {
      this.renderTelemetryPanels(data.telemetry);
    }

    // Update Map
    const hostLoc = this.hostInfo ? this.hostInfo.host_location : null;
    this.map.updateConnections(this.allConnections, hostLoc);

    // Apply table filter and render
    this.applyFilterAndRender();
  }

  renderTelemetryPanels(telemetry) {
    // Top Countries
    const countriesList = document.getElementById('telemetryTopCountries');
    if (countriesList && telemetry.top_countries) {
      countriesList.innerHTML = telemetry.top_countries.map(c => `
        <div class="mb-2">
          <div class="flex justify-between text-xs mb-1 font-mono">
            <span class="text-slate-300 truncate">${c.country}</span>
            <span class="text-cyan-400 font-semibold">${c.count} (${c.percentage}%)</span>
          </div>
          <div class="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div class="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full" style="width: ${c.percentage}%"></div>
          </div>
        </div>
      `).join('');
    }

    // Top Processes
    const processList = document.getElementById('telemetryTopProcesses');
    if (processList && telemetry.top_processes) {
      processList.innerHTML = telemetry.top_processes.map(p => `
        <div class="flex items-center justify-between py-1 border-b border-slate-800/60 text-xs">
          <span class="font-mono text-slate-300 truncate max-w-[140px]">${p.name}</span>
          <span class="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-mono text-[11px]">${p.count} sockets</span>
        </div>
      `).join('');
    }

    // Protocols Breakdown
    const protoContainer = document.getElementById('telemetryProtocols');
    if (protoContainer && telemetry.top_protocols) {
      protoContainer.innerHTML = telemetry.top_protocols.map(p => `
        <div class="flex items-center justify-between py-1 border-b border-slate-800/60 text-xs">
          <span class="font-semibold text-slate-300">${p.protocol}</span>
          <span class="font-mono text-cyan-300">${p.count}</span>
        </div>
      `).join('');
    }
  }

  applyFilterAndRender() {
    this.filteredConnections = this.allConnections.filter(c => {
      // Protocol / Threat Filter
      if (this.protocolFilter !== 'ALL') {
        if (this.protocolFilter === 'THREAT') {
          const t = c.threat_intel;
          if (!t || (!t.is_threat && t.verdict !== 'SUSPICIOUS')) return false;
        } else if (this.protocolFilter === 'HTTPS' && c.protocol !== 'HTTPS' && c.protocol !== 'HTTP') return false;
        else if (this.protocolFilter === 'DNS' && c.protocol !== 'DNS') return false;
        else if (this.protocolFilter === 'SSH' && c.protocol !== 'SSH' && c.protocol !== 'RDP') return false;
        else if (this.protocolFilter === 'OTHER' && ['HTTPS', 'HTTP', 'DNS', 'SSH', 'RDP'].includes(c.protocol)) return false;
      }

      // Search Query
      if (this.searchQuery) {
        const query = this.searchQuery;
        const proc = (c.process || '').toLowerCase();
        const lIp = (c.source.ip || '').toLowerCase();
        const rIp = (c.destination ? c.destination.ip : '').toLowerCase();
        const proto = (c.protocol || '').toLowerCase();
        const status = (c.status || '').toLowerCase();
        const country = (c.destination && c.destination.geo ? c.destination.geo.country : '').toLowerCase();
        const city = (c.destination && c.destination.geo ? c.destination.geo.city : '').toLowerCase();

        return proc.includes(query) || lIp.includes(query) || rIp.includes(query) ||
               proto.includes(query) || status.includes(query) || country.includes(query) || city.includes(query);
      }

      return true;
    });

    this.renderTable();
  }

  renderTable() {
    const tbody = document.getElementById('connectionsTableBody');
    const countBadge = document.getElementById('tableFilteredCount');
    if (countBadge) countBadge.textContent = `${this.filteredConnections.length} shown`;

    if (!tbody) return;

    if (this.filteredConnections.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" class="text-center py-8 text-slate-500 font-mono text-sm">
            No active connections match the current filter criteria.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = this.filteredConnections.slice(0, 150).map(c => {
      const isRemote = Boolean(c.destination && c.destination.ip);
      const dstGeo = c.destination ? c.destination.geo : null;
      const remoteLoc = dstGeo ? `${dstGeo.city || 'LAN'}, ${dstGeo.country || 'Host'}` : 'Listening Socket';
      const remoteFlag = dstGeo && dstGeo.country_code && dstGeo.country_code !== 'LOC' ? `[${dstGeo.country_code}]` : '🏠';

      // Protocol Color Badge
      let protoBadgeClass = "bg-slate-800 text-slate-300 border-slate-700";
      if (c.protocol === 'HTTPS' || c.protocol === 'HTTP') protoBadgeClass = "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
      else if (c.protocol === 'DNS') protoBadgeClass = "bg-sky-500/15 text-sky-400 border-sky-500/30";
      else if (c.protocol === 'SSH' || c.protocol === 'RDP') protoBadgeClass = "bg-amber-500/15 text-amber-400 border-amber-500/30";

      // Status Badge
      let statusClass = "text-slate-400";
      if (c.status === 'ESTABLISHED') statusClass = "text-cyan-400 font-semibold";
      else if (c.status === 'LISTEN') statusClass = "text-slate-400 italic";
      else if (c.status === 'SYN_SENT' || c.status === 'TIME_WAIT') statusClass = "text-amber-400";

      // Direction Badge
      let dirClass = "text-slate-400";
      if (c.direction === 'Inbound') dirClass = "text-purple-400 bg-purple-500/10";
      else if (c.direction === 'Outbound') dirClass = "text-cyan-400 bg-cyan-500/10";

      // Threat Intel Reputation Badge
      const threat = c.threat_intel;
      let threatBadge = `<span class="px-2 py-0.5 rounded font-mono text-[10px] bg-slate-800 text-slate-400 border border-slate-700/60">CLEAN</span>`;
      let isThreatRow = false;
      if (threat && threat.is_threat) {
        isThreatRow = true;
        threatBadge = `<span class="px-2 py-0.5 rounded font-mono text-[10px] bg-rose-500/20 text-rose-300 border border-rose-500/60 font-bold flex items-center w-fit shadow-[0_0_8px_rgba(244,63,94,0.3)]"><span class="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping mr-1"></span>⚠️ ${threat.category || 'MALICIOUS'}</span>`;
      } else if (threat && threat.verdict === 'SUSPICIOUS') {
        threatBadge = `<span class="px-2 py-0.5 rounded font-mono text-[10px] bg-amber-500/20 text-amber-300 border border-amber-500/50 font-semibold w-fit">⚡ ${threat.category || 'SUSPICIOUS'}</span>`;
      }

      const rowBorderClass = isThreatRow ? "border-rose-500/30 bg-rose-950/20" : "border-slate-800/40 hover:bg-slate-800/30";

      return `
        <tr class="border-b ${rowBorderClass} text-xs transition">
          <!-- Process -->
          <td class="py-2.5 px-3">
            <div class="flex items-center space-x-2">
              <span class="font-mono font-medium text-slate-200 truncate max-w-[130px]" title="${c.process}">${c.process}</span>
              ${c.pid ? `<span class="px-1.5 py-0.2 bg-slate-800 text-slate-400 font-mono text-[10px] rounded border border-slate-700">PID ${c.pid}</span>` : ''}
            </div>
          </td>

          <!-- Protocol -->
          <td class="py-2.5 px-3">
            <span class="px-2 py-0.5 rounded font-mono text-[11px] border ${protoBadgeClass}">${c.protocol}</span>
          </td>

          <!-- Local Endpoint -->
          <td class="py-2.5 px-3 font-mono text-slate-300">
            ${c.source.ip}:${c.source.port}
          </td>

          <!-- Direction -->
          <td class="py-2.5 px-3">
            <span class="px-1.5 py-0.5 rounded text-[10px] uppercase font-mono ${dirClass}">${c.direction}</span>
          </td>

          <!-- Remote Endpoint & Geo -->
          <td class="py-2.5 px-3">
            ${isRemote ? `
              <div class="font-mono text-cyan-300 cursor-pointer hover:underline flex items-center space-x-1" onclick="window.AegisAppInstance.inspector.inspect('${c.destination.ip}', ${JSON.stringify(c).replace(/"/g, '&quot;')})">
                <span>${remoteFlag}</span>
                <span class="font-bold">${c.destination.ip}</span>
                <span class="text-slate-400">:${c.destination.port}</span>
              </div>
              <div class="text-[11px] text-slate-400 truncate max-w-[180px]">${remoteLoc}</div>
            ` : `
              <span class="text-slate-500 italic font-mono">Listening on *:${c.source.port}</span>
            `}
          </td>

          <!-- Threat Intel Reputation -->
          <td class="py-2.5 px-3">
            ${threatBadge}
          </td>

          <!-- Status -->
          <td class="py-2.5 px-3 font-mono ${statusClass}">
            ${c.status}
          </td>

          <!-- Actions -->
          <td class="py-2.5 px-3 text-right">
            <div class="flex items-center justify-end space-x-1">
              ${isRemote ? `
                <button title="Deep Inspect" onclick="window.AegisAppInstance.inspector.inspect('${c.destination.ip}', ${JSON.stringify(c).replace(/"/g, '&quot;')})" class="p-1 rounded bg-slate-800 hover:bg-cyan-500/20 text-slate-300 hover:text-cyan-300 transition">
                  <i data-lucide="search" class="w-3.5 h-3.5"></i>
                </button>
                <button title="Block IP via Firewall" onclick="window.AegisAppInstance.quickBlockIP('${c.destination.ip}')" class="p-1 rounded bg-slate-800 hover:bg-rose-500/20 text-slate-300 hover:text-rose-400 transition">
                  <i data-lucide="shield-alert" class="w-3.5 h-3.5"></i>
                </button>
              ` : ''}
              ${c.pid && c.pid > 4 ? `
                <button title="Terminate Process" onclick="window.AegisAppInstance.quickTerminateProcess(${c.pid}, '${c.process}')" class="p-1 rounded bg-slate-800 hover:bg-amber-500/20 text-slate-300 hover:text-amber-400 transition">
                  <i data-lucide="power" class="w-3.5 h-3.5"></i>
                </button>
              ` : ''}
            </div>
          </td>
        </tr>
      `;
    }).join('');

    if (window.lucide) window.lucide.createIcons();
  }

  async quickBlockIP(ip) {
    if (!confirm(`Execute OS firewall rule to block all inbound and outbound traffic with ${ip}?`)) return;
    try {
      const resp = await fetch('/api/actions/block-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip, reason: "Quick Table Block" })
      });
      const data = await resp.json();
      if (resp.ok && (data.success || data.requires_admin)) {
        this.audio.play('block');
        window.AegisUI.showToast(`Firewall block rule executed for ${ip}`, 'warning');
        window.AegisUI.logEvent(`🛡️ Quick Firewall Block: ${ip}`, 'warning');
        if (this.inspector) this.inspector.refreshBlockedList();
      } else {
        window.AegisUI.showToast(`Block failed: ${data.detail || data.error}`, 'error');
      }
    } catch (e) {
      window.AegisUI.showToast(`Error: ${e.message}`, 'error');
    }
  }

  async quickTerminateProcess(pid, name) {
    if (!confirm(`Immediately terminate process ${name} (PID: ${pid})?`)) return;
    try {
      const resp = await fetch('/api/actions/terminate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid: pid })
      });
      const data = await resp.json();
      if (resp.ok && data.success) {
        this.audio.play('kill');
        window.AegisUI.showToast(`Process ${name} (PID: ${pid}) terminated`, 'success');
        window.AegisUI.logEvent(`⚡ Process Terminated: ${name} [PID ${pid}]`, 'alert');
      } else {
        window.AegisUI.showToast(`Failed: ${data.detail || data.error}`, 'error');
      }
    } catch (e) {
      window.AegisUI.showToast(`Error: ${e.message}`, 'error');
    }
  }

  async loadFirewallRules() {
    const tbody = document.getElementById('firewallRulesTableBody');
    if (!tbody) return;
    tbody.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-slate-400 font-mono text-xs">Querying OS firewall rules...</td></tr>`;

    try {
      const resp = await fetch('/api/firewall/rules');
      const data = await resp.json();
      const rules = data.rules || [];

      if (rules.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-slate-500 font-mono text-xs">No active AegisNet firewall block rules found.</td></tr>`;
        return;
      }

      tbody.innerHTML = rules.map(r => `
        <tr class="border-b border-slate-800 text-xs">
          <td class="py-2.5 px-3 font-mono font-bold text-rose-400">${r.ip}</td>
          <td class="py-2.5 px-3 text-slate-300 font-mono text-[11px]">${r.formatted_time || 'N/A'}</td>
          <td class="py-2.5 px-3 text-slate-400">${r.reason || 'SOC Block'}</td>
          <td class="py-2.5 px-3">
            <span class="px-2 py-0.5 rounded text-[10px] font-mono ${r.status === 'Active' ? 'bg-rose-500/20 text-rose-300' : 'bg-amber-500/20 text-amber-300'}">${r.status}</span>
          </td>
          <td class="py-2.5 px-3 text-right">
            <button onclick="window.AegisAppInstance.unblockRule('${r.ip}')" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition font-mono text-[11px]">
              Unblock
            </button>
          </td>
        </tr>
      `).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-rose-400 font-mono text-xs">Failed to load rules: ${e.message}</td></tr>`;
    }
  }

  async unblockRule(ip) {
    try {
      const resp = await fetch('/api/actions/unblock-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
      });
      const data = await resp.json();
      if (resp.ok && data.success) {
        window.AegisUI.showToast(`Unblocked ${ip}`, 'info');
        window.AegisUI.logEvent(`🔓 Firewall Rule Deleted: ${ip}`, 'info');
        this.loadFirewallRules();
        if (this.inspector) this.inspector.refreshBlockedList();
      }
    } catch (e) {
      window.AegisUI.showToast(`Error: ${e.message}`, 'error');
    }
  }
}

// Global UI helper for toasts and audit logs
window.AegisUI = {
  showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    let borderCol = 'border-cyan-500/50';
    let icon = 'info';

    if (type === 'success') {
      borderCol = 'border-emerald-500/50 text-emerald-300';
      icon = 'check-circle';
    } else if (type === 'warning') {
      borderCol = 'border-amber-500/50 text-amber-300';
      icon = 'alert-triangle';
    } else if (type === 'error' || type === 'alert') {
      borderCol = 'border-rose-500/50 text-rose-300';
      icon = 'alert-octagon';
    }

    toast.className = `cyber-card flex items-center space-x-2.5 px-4 py-2.5 rounded border ${borderCol} text-xs font-mono shadow-2xl transition-all duration-300 transform translate-y-2 opacity-0`;
    toast.innerHTML = `<i data-lucide="${icon}" class="w-4 h-4"></i><span>${message}</span>`;
    container.appendChild(toast);

    if (window.lucide) window.lucide.createIcons();

    setTimeout(() => {
      toast.classList.remove('translate-y-2', 'opacity-0');
    }, 10);

    setTimeout(() => {
      toast.classList.add('opacity-0', 'translate-y-2');
      setTimeout(() => toast.remove(), 350);
    }, 3500);
  },

  logEvent(msg, level = 'info') {
    const logBox = document.getElementById('telemetryEventLog');
    if (!logBox) return;

    const row = document.createElement('div');
    const timeStr = new Date().toLocaleTimeString();
    let col = 'text-slate-400';
    if (level === 'warning') col = 'text-amber-400';
    if (level === 'alert') col = 'text-rose-400 font-semibold';

    row.className = `py-0.5 font-mono text-[11px] ${col} truncate`;
    row.innerHTML = `<span class="text-slate-600 mr-1.5">[${timeStr}]</span> ${msg}`;
    logBox.insertBefore(row, logBox.firstChild);

    while (logBox.children.length > 30) {
      logBox.removeChild(logBox.lastChild);
    }
  }
};

window.addEventListener('DOMContentLoaded', () => {
  window.AegisAppInstance = new AegisApp();
  if (window.lucide) window.lucide.createIcons();
});
