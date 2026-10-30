/**
 * AegisNet IP & Socket Deep Inspector Drawer
 * Handles deep GeoIP intelligence, process inspection, process termination, and firewall bans.
 */

class IPInspector {
  constructor(options = {}) {
    this.drawerEl = document.getElementById('inspectorDrawer');
    this.onActionSuccess = options.onActionSuccess || (() => {});
    this.onFlyToMap = options.onFlyToMap || (() => {});
    this.playAudio = options.playAudio || (() => {});
    this.currentData = null;
    this.blockedIPsSet = new Set();

    this.bindEvents();
    this.refreshBlockedList();
  }

  bindEvents() {
    const closeBtn = document.getElementById('closeInspectorBtn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => this.close());
    }

    // Backdrop click
    const backdrop = document.getElementById('inspectorBackdrop');
    if (backdrop) {
      backdrop.addEventListener('click', () => this.close());
    }

    // Terminate Button
    const termBtn = document.getElementById('inspectorTerminateBtn');
    if (termBtn) {
      termBtn.addEventListener('click', () => this.handleTerminate());
    }

    // Block Button
    const blockBtn = document.getElementById('inspectorBlockBtn');
    if (blockBtn) {
      blockBtn.addEventListener('click', () => this.handleBlock());
    }

    // Unblock Button
    const unblockBtn = document.getElementById('inspectorUnblockBtn');
    if (unblockBtn) {
      unblockBtn.addEventListener('click', () => this.handleUnblock());
    }

    // Copy IP Button
    const copyBtn = document.getElementById('inspectorCopyBtn');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        if (this.currentData && this.currentData.ip) {
          navigator.clipboard.writeText(this.currentData.ip);
          window.AegisUI.showToast(`IP ${this.currentData.ip} copied to clipboard`, 'info');
        }
      });
    }

    // Locate on Map Button
    const locateBtn = document.getElementById('inspectorLocateBtn');
    if (locateBtn) {
      locateBtn.addEventListener('click', () => {
        if (this.currentData && this.currentData.geo && typeof this.currentData.geo.lat === 'number') {
          this.onFlyToMap(this.currentData.geo.lat, this.currentData.geo.lon, 7);
          this.close();
        }
      });
    }
  }

  async refreshBlockedList() {
    try {
      const resp = await fetch('/api/firewall/rules');
      const data = await resp.json();
      if (data && data.rules) {
        this.blockedIPsSet = new Set(data.rules.map(r => r.ip));
        this.updateBlockButtonState();
      }
    } catch (e) {
      console.warn("Could not fetch blocked rules:", e);
    }
  }

  updateBlockButtonState() {
    const blockBtn = document.getElementById('inspectorBlockBtn');
    const unblockBtn = document.getElementById('inspectorUnblockBtn');
    const blockedBadge = document.getElementById('inspectorBlockedBadge');

    if (!this.currentData || !this.currentData.ip) return;

    const isBlocked = this.blockedIPsSet.has(this.currentData.ip);

    if (isBlocked) {
      if (blockBtn) blockBtn.classList.add('hidden');
      if (unblockBtn) unblockBtn.classList.remove('hidden');
      if (blockedBadge) blockedBadge.classList.remove('hidden');
    } else {
      if (blockBtn) blockBtn.classList.remove('hidden');
      if (unblockBtn) unblockBtn.classList.add('hidden');
      if (blockedBadge) blockedBadge.classList.add('hidden');
    }
  }

  async inspect(ip, connContext = null) {
    if (!ip) return;

    this.drawerEl.classList.remove('translate-x-full');
    const backdrop = document.getElementById('inspectorBackdrop');
    if (backdrop) backdrop.classList.remove('hidden');

    // Set preliminary data
    document.getElementById('inspectorIP').textContent = ip;
    document.getElementById('inspectorCityCountry').textContent = 'Querying GeoIP telemetry...';
    document.getElementById('inspectorISP').textContent = 'Resolving...';
    document.getElementById('inspectorASN').textContent = 'Resolving...';
    document.getElementById('inspectorOrg').textContent = 'Resolving...';
    document.getElementById('inspectorCoords').textContent = '...';

    // External threat intelligence links
    document.getElementById('linkVirusTotal').href = `https://www.virustotal.com/gui/ip-address/${ip}`;
    document.getElementById('linkAbuseIPDB').href = `https://www.abuseipdb.com/check/${ip}`;
    document.getElementById('linkShodan').href = `https://www.shodan.io/host/${ip}`;

    // Fill process & socket context
    if (connContext) {
      document.getElementById('inspectorPID').textContent = connContext.pid || 'N/A';
      document.getElementById('inspectorProcessName').textContent = connContext.process || 'Unknown';
      document.getElementById('inspectorProcessPath').textContent = connContext.process_exe || 'N/A';
      document.getElementById('inspectorProtocol').textContent = connContext.protocol || 'TCP';
      document.getElementById('inspectorState').textContent = connContext.status || 'N/A';
      document.getElementById('inspectorLocalEndpoint').textContent = `${connContext.source.ip}:${connContext.source.port}`;
      document.getElementById('inspectorRemoteEndpoint').textContent = `${connContext.destination ? connContext.destination.ip : ''}:${connContext.destination ? connContext.destination.port : ''}`;
      
      const termBtn = document.getElementById('inspectorTerminateBtn');
      if (termBtn) {
        termBtn.disabled = !connContext.pid || connContext.pid <= 4;
      }
    } else {
      document.getElementById('inspectorPID').textContent = 'N/A';
      document.getElementById('inspectorProcessName').textContent = 'Detached / Historic';
      document.getElementById('inspectorProcessPath').textContent = 'N/A';
      document.getElementById('inspectorLocalEndpoint').textContent = 'N/A';
      document.getElementById('inspectorRemoteEndpoint').textContent = ip;
      const termBtn = document.getElementById('inspectorTerminateBtn');
      if (termBtn) termBtn.disabled = true;
    }

    try {
      const resp = await fetch(`/api/geoip/lookup/${ip}`);
      const geo = await resp.json();

      this.currentData = {
        ip: ip,
        geo: geo,
        conn: connContext
      };

      document.getElementById('inspectorCityCountry').textContent = `${geo.city || 'Unknown'}, ${geo.country || 'Unknown'}`;
      document.getElementById('inspectorISP').textContent = geo.isp || 'N/A';
      document.getElementById('inspectorASN').textContent = geo.asn || 'N/A';
      document.getElementById('inspectorOrg').textContent = geo.org || 'N/A';
      document.getElementById('inspectorCoords').textContent = `${(geo.lat || 0).toFixed(4)}, ${(geo.lon || 0).toFixed(4)}`;

      // Private/LAN badge
      const privBadge = document.getElementById('inspectorPrivateBadge');
      if (privBadge) {
        if (geo.is_private) {
          privBadge.classList.remove('hidden');
        } else {
          privBadge.classList.add('hidden');
        }
      }

      this.updateBlockButtonState();
    } catch (e) {
      console.error("Failed to lookup GeoIP:", e);
    }

    // Live Threat Intelligence Reputation Query
    try {
      const intelRes = await fetch(`/api/intel/lookup?ip=${encodeURIComponent(ip)}`);
      const intel = await intelRes.json();
      const threatBox = document.getElementById('inspectorThreatBanner');
      if (threatBox) {
        if (intel.is_threat) {
          threatBox.className = "p-3 rounded-lg bg-rose-950/70 border border-rose-500 text-rose-200 text-xs font-mono shadow-lg shadow-rose-950/50";
          threatBox.innerHTML = `
            <div class="flex items-center justify-between font-bold mb-1">
              <span class="flex items-center text-rose-300"><span class="w-2 h-2 rounded-full bg-rose-500 animate-ping mr-1.5"></span>⚠️ MALICIOUS ENDPOINT</span>
              <span class="text-rose-400 font-bold">${intel.score}/100</span>
            </div>
            <div class="text-[11px] text-rose-200">${intel.category}</div>
            <div class="text-[10px] text-rose-300/80 mt-1">&bull; ${(intel.indicators || []).join(' &bull; ')}</div>
          `;
        } else if (intel.verdict === 'SUSPICIOUS') {
          threatBox.className = "p-3 rounded-lg bg-amber-950/70 border border-amber-500 text-amber-200 text-xs font-mono shadow-lg";
          threatBox.innerHTML = `
            <div class="flex items-center justify-between font-bold mb-1">
              <span class="text-amber-300">⚡ SUSPICIOUS ACTIVITY</span>
              <span class="text-amber-400 font-bold">${intel.score}/100</span>
            </div>
            <div class="text-[11px] text-amber-200">${intel.category}</div>
            <div class="text-[10px] text-amber-300/80 mt-1">&bull; ${(intel.indicators || []).join(' &bull; ')}</div>
          `;
        } else {
          threatBox.className = "p-2.5 rounded-lg bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs font-mono";
          threatBox.innerHTML = `
            <div class="flex items-center justify-between">
              <span class="flex items-center"><i data-lucide="shield-check" class="w-3.5 h-3.5 text-emerald-400 mr-1.5"></i> CLEAN REPUTATION</span>
              <span class="text-[10px] text-slate-400">Risk Score: ${intel.score}/100</span>
            </div>
          `;
        }
      }
    } catch (err) {
      console.debug("Failed threat query in inspector:", err);
    }

    if (window.lucide) {
      window.lucide.createIcons();
    }
  }

  async handleTerminate() {
    if (!this.currentData || !this.currentData.conn || !this.currentData.conn.pid) {
      window.AegisUI.showToast("No active PID associated with this connection.", "warning");
      return;
    }

    const pid = this.currentData.conn.pid;
    const procName = this.currentData.conn.process || 'Process';

    if (!confirm(`Are you sure you want to terminate ${procName} (PID: ${pid})? This will immediately sever all active sockets.`)) {
      return;
    }

    const termBtn = document.getElementById('inspectorTerminateBtn');
    if (termBtn) {
      termBtn.disabled = true;
      termBtn.innerHTML = `<span class="animate-spin inline-block mr-1">⏳</span> Terminating...`;
    }

    try {
      const resp = await fetch('/api/actions/terminate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid: pid })
      });

      const res = await resp.json();
      if (resp.ok && res.success) {
        this.playAudio('kill');
        window.AegisUI.showToast(`Terminated ${procName} (PID: ${pid})`, 'success');
        window.AegisUI.logEvent(`⚡ Process Terminated: ${procName} [PID ${pid}]`, 'alert');
        this.onActionSuccess();
        setTimeout(() => this.close(), 600);
      } else {
        window.AegisUI.showToast(`Termination failed: ${res.detail || res.error || 'Access Denied'}`, 'error');
      }
    } catch (e) {
      window.AegisUI.showToast(`Error: ${e.message}`, 'error');
    } finally {
      if (termBtn) {
        termBtn.disabled = false;
        termBtn.innerHTML = `<i data-lucide="power" class="w-4 h-4 mr-1.5"></i> Terminate Connection`;
        if (window.lucide) window.lucide.createIcons();
      }
    }
  }

  async handleBlock() {
    if (!this.currentData || !this.currentData.ip) return;
    const ip = this.currentData.ip;

    if (!confirm(`PERMANENT FIREWALL BLOCK:\nAre you sure you want to execute native OS firewall rules (netsh/iptables) to permanently DROP all inbound & outbound traffic with ${ip}?`)) {
      return;
    }

    const blockBtn = document.getElementById('inspectorBlockBtn');
    if (blockBtn) {
      blockBtn.disabled = true;
      blockBtn.innerHTML = `<span class="animate-spin inline-block mr-1">⏳</span> Applying Rule...`;
    }

    try {
      const resp = await fetch('/api/actions/block-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip, reason: "Operator Inspector Action" })
      });

      const res = await resp.json();
      if (resp.ok && (res.success || res.requires_admin)) {
        this.playAudio('block');
        this.blockedIPsSet.add(ip);
        this.updateBlockButtonState();
        
        const note = res.requires_admin ? " (Note: Administrator elevation required to enforce rule)" : "";
        window.AegisUI.showToast(`Firewall Rule Added: Blocked ${ip}${note}`, res.requires_admin ? 'warning' : 'success');
        window.AegisUI.logEvent(`🛡️ Firewall Block Rule: ${ip} [Inbound & Outbound]`, 'warning');
        this.onActionSuccess();
      } else {
        window.AegisUI.showToast(`Firewall block failed: ${res.detail || res.error}`, 'error');
      }
    } catch (e) {
      window.AegisUI.showToast(`Error: ${e.message}`, 'error');
    } finally {
      if (blockBtn) {
        blockBtn.disabled = false;
        blockBtn.innerHTML = `<i data-lucide="shield-alert" class="w-4 h-4 mr-1.5"></i> Permanent Firewall Block`;
        if (window.lucide) window.lucide.createIcons();
      }
    }
  }

  async handleUnblock() {
    if (!this.currentData || !this.currentData.ip) return;
    const ip = this.currentData.ip;

    try {
      const resp = await fetch('/api/actions/unblock-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
      });

      const res = await resp.json();
      if (resp.ok && res.success) {
        this.blockedIPsSet.delete(ip);
        this.updateBlockButtonState();
        window.AegisUI.showToast(`Firewall block rules deleted for ${ip}`, 'info');
        window.AegisUI.logEvent(`🔓 Firewall Rule Deleted: ${ip} unblocked`, 'info');
        this.onActionSuccess();
      }
    } catch (e) {
      window.AegisUI.showToast(`Unblock failed: ${e.message}`, 'error');
    }
  }

  close() {
    this.drawerEl.classList.add('translate-x-full');
    const backdrop = document.getElementById('inspectorBackdrop');
    if (backdrop) backdrop.classList.add('hidden');
  }
}

window.IPInspector = IPInspector;
