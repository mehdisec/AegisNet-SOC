/**
 * AegisNet Interactive World Map & Curved Particle Arcs Engine
 * ZERO-API-KEY ARCHITECTURE:
 * 1. Bundled Local GeoJSON Vector Basemap (100% Offline, Zero API Key)
 * 2. Optional OpenStreetMap Dark Inversion Layer (Zero API Key)
 * 3. HTML5 Canvas Curved Quadratic Bezier Particle Arcs with Hit-Testing & Link Selection
 * 4. Destination Anchor Points & Protocol Filtering
 */

class AegisMap {
  constructor(containerId, options = {}) {
    this.containerId = containerId;
    this.container = document.getElementById(containerId);
    this.onSelectIP = options.onSelectIP || (() => {});
    
    this.map = null;
    this.canvas = null;
    this.ctx = null;
    this.animationFrameId = null;

    this.geoJsonLayer = null;
    this.tileLayer = null;
    this.currentMode = 'vector'; // 'vector' or 'osm'
    this.protocolFilter = 'ALL';

    this.hostLocation = { lat: 37.7749, lon: -122.4194, city: "Host", country: "Local" };
    this.hostMarker = null;
    this.remoteMarkers = new Map(); // ip -> L.marker
    this.activeArcs = [];           // list of arc objects to render
    this.lastRawConnections = [];

    this.hoveredArc = null;
    this.selectedArcId = null;
    
    this.initMap();
    this.loadVectorBasemap();
    this.initCanvasOverlay();
    this.bindInteractions();
    this.startAnimationLoop();
  }

  initMap() {
    this.map = L.map(this.containerId, {
      center: [25, 10],
      zoom: 2.2,
      minZoom: 1.5,
      maxZoom: 14,
      zoomControl: true,
      worldCopyJump: true,
      attributionControl: false
    });

    this.map.zoomControl.setPosition('bottomright');

    // Create dedicated top-level tooltip pane outside mapPane so tooltips are strictly on the highest layer
    this.map.createPane('topTooltipPane', this.container);
    this.map.getPane('topTooltipPane').style.zIndex = '10000';
    this.map.getPane('topTooltipPane').style.pointerEvents = 'none';

    setTimeout(() => {
      if (this.map) this.map.invalidateSize();
    }, 250);
  }

  loadVectorBasemap() {
    if (window.WORLD_GEOJSON) {
      this.renderGeoJson(window.WORLD_GEOJSON);
    } else {
      fetch('/static/data/world.geojson')
        .then(res => res.json())
        .then(data => {
          window.WORLD_GEOJSON = data;
          this.renderGeoJson(data);
        })
        .catch(err => {
          console.warn("Could not load local world.geojson, activating OSM dark fallback:", err);
          this.enableOsmTiles();
        });
    }
  }

  renderGeoJson(geoData) {
    if (this.geoJsonLayer) {
      this.map.removeLayer(this.geoJsonLayer);
    }

    this.geoJsonLayer = L.geoJSON(geoData, {
      style: () => ({
        fillColor: '#0b1322',
        fillOpacity: 0.95,
        color: '#00f3ff',
        weight: 0.75,
        opacity: 0.35
      }),
      onEachFeature: (feature, layer) => {
        const countryName = (feature.properties && (feature.properties.name || feature.properties.admin)) || 'Region';
        layer.bindTooltip(countryName, {
          sticky: true,
          className: 'cyber-country-tooltip',
          pane: 'topTooltipPane',
          offset: [0, -10]
        });

        layer.on('mouseover', () => {
          layer.setStyle({
            fillColor: '#16233d',
            fillOpacity: 0.98,
            color: '#00f3ff',
            weight: 1.5,
            opacity: 0.9
          });
        });

        layer.on('mouseout', () => {
          if (this.geoJsonLayer) {
            this.geoJsonLayer.resetStyle(layer);
          }
        });
      }
    }).addTo(this.map);
  }

  toggleBasemapMode() {
    if (this.currentMode === 'vector') {
      this.enableOsmTiles();
      this.currentMode = 'osm';
      return 'OSM Dark Tiles';
    } else {
      this.enableVectorMap();
      this.currentMode = 'vector';
      return 'Offline Vector Map';
    }
  }

  enableOsmTiles() {
    if (this.geoJsonLayer) {
      this.map.removeLayer(this.geoJsonLayer);
    }
    if (!this.tileLayer) {
      this.tileLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        subdomains: ['a', 'b', 'c'],
        maxZoom: 18,
        className: 'osm-dark-tiles'
      });
    }
    this.tileLayer.addTo(this.map);
  }

  enableVectorMap() {
    if (this.tileLayer) {
      this.map.removeLayer(this.tileLayer);
    }
    if (this.geoJsonLayer) {
      this.geoJsonLayer.addTo(this.map);
    } else {
      this.loadVectorBasemap();
    }
  }

  initCanvasOverlay() {
    this.canvas = document.createElement('canvas');
    this.canvas.id = 'arcCanvas';
    this.container.appendChild(this.canvas);
    this.ctx = this.canvas.getContext('2d');

    const resizeCanvas = () => {
      const rect = this.container.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      this.canvas.width = rect.width * dpr;
      this.canvas.height = rect.height * dpr;
      this.canvas.style.width = `${rect.width}px`;
      this.canvas.style.height = `${rect.height}px`;
      this.ctx.scale(dpr, dpr);
    };

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // Sync on Leaflet move & zoom
    this.map.on('move', () => this.drawArcs());
    this.map.on('zoom', () => this.drawArcs());
    this.map.on('resize', () => {
      resizeCanvas();
      this.drawArcs();
    });
  }

  bindInteractions() {
    // Mouse hover detection over link arcs
    this.map.on('mousemove', (e) => this.handleMapMouseMove(e));
    // Click selection on link arcs
    this.map.on('click', (e) => this.handleMapClick(e));
  }

  setProtocolFilter(proto) {
    this.protocolFilter = proto || 'ALL';
    if (this.lastRawConnections && this.lastRawConnections.length > 0) {
      this.updateConnections(this.lastRawConnections, this.hostLocation);
    }
  }

  setHostLocation(loc) {
    if (!loc || typeof loc.lat !== 'number' || typeof loc.lon !== 'number') return;
    this.hostLocation = loc;

    if (this.hostMarker) {
      this.hostMarker.setLatLng([loc.lat, loc.lon]);
    } else {
      const hostIcon = L.divIcon({
        className: 'host-marker-wrapper',
        html: `<div class="host-marker-pin" title="Local Host Station"></div>`,
        iconSize: [24, 24],
        iconAnchor: [12, 12]
      });

      this.hostMarker = L.marker([loc.lat, loc.lon], { icon: hostIcon, zIndexOffset: 1000 })
        .addTo(this.map)
        .bindPopup(`
          <div class="text-xs font-mono p-1">
            <div class="font-bold text-cyan-400 uppercase tracking-wider mb-1">🛡️ Host Monitoring Station</div>
            <div class="text-slate-100 font-medium">${loc.city || 'LAN'}, ${loc.country || 'Host'}</div>
            <div class="text-slate-400 text-[10px] mt-1">LAT: ${loc.lat.toFixed(4)}, LON: ${loc.lon.toFixed(4)}</div>
          </div>
        `);
    }
  }

  updateConnections(connections, hostLoc) {
    this.lastRawConnections = connections || [];
    if (hostLoc) {
      this.setHostLocation(hostLoc);
    }

    const currentIPs = new Set();
    const newArcs = [];

    // Protocol filter matching
    const shouldIncludeProtocol = (proto) => {
      if (!this.protocolFilter || this.protocolFilter === 'ALL') return true;
      if (this.protocolFilter === 'HTTPS') return proto === 'HTTPS' || proto === 'HTTP';
      if (this.protocolFilter === 'DNS') return proto === 'DNS';
      if (this.protocolFilter === 'SSH') return proto === 'SSH' || proto === 'RDP';
      if (this.protocolFilter === 'OTHER') return !['HTTPS', 'HTTP', 'DNS', 'SSH', 'RDP'].includes(proto);
      return proto === this.protocolFilter;
    };

    connections.forEach((conn, index) => {
      if (!conn.destination || !conn.destination.geo) return;
      if (!shouldIncludeProtocol(conn.protocol)) return;

      const dstGeo = conn.destination.geo;
      const dstIP = conn.destination.ip;
      if (!dstIP || dstGeo.is_private) return;

      const dLat = dstGeo.lat;
      const dLon = dstGeo.lon;
      if (typeof dLat !== 'number' || typeof dLon !== 'number' || (dLat === 0 && dLon === 0)) return;

      currentIPs.add(dstIP);

      // Arc Source & Destination coordinates
      const sLat = (conn.source && conn.source.geo && typeof conn.source.geo.lat === 'number') 
        ? conn.source.geo.lat 
        : this.hostLocation.lat;
      const sLon = (conn.source && conn.source.geo && typeof conn.source.geo.lon === 'number') 
        ? conn.source.geo.lon 
        : this.hostLocation.lon;

      // Color scheme based on protocol / risk
      let color = '#00f3ff'; // Default cyan
      if (conn.protocol === 'HTTPS' || conn.protocol === 'HTTP') color = '#00ff88'; // Emerald
      else if (conn.protocol === 'DNS') color = '#38bdf8'; // Sky blue
      else if (conn.protocol === 'SSH' || conn.protocol === 'RDP') color = '#ffaa00'; // Amber
      else if (conn.status === 'SYN_SENT' || conn.status === 'TIME_WAIT') color = '#f43f5e'; // Rose

      newArcs.push({
        id: conn.id,
        sLat, sLon,
        dLat, dLon,
        color,
        speed: 0.00012 + ((index % 4) * 0.00003), // Slower, smooth packet flow
        offset: (index * 0.17) % 1.0,
        protocol: conn.protocol,
        process: conn.process,
        dstIP: dstIP,
        connContext: conn,
        renderedPoints: null // cached during drawArcs for hit-testing
      });

      // Update Remote Markers with Destination IP Pill Label
      if (this.remoteMarkers.has(dstIP)) {
        // Coordinate sync if GeoIP updated
        const existingMarker = this.remoteMarkers.get(dstIP);
        const curPos = existingMarker.getLatLng();
        if (Math.abs(curPos.lat - dLat) > 0.001 || Math.abs(curPos.lng - dLon) > 0.001) {
          existingMarker.setLatLng([dLat, dLon]);
        }
      } else {
        const markerIcon = L.divIcon({
          className: 'remote-marker-wrapper',
          html: `
            <div class="remote-marker-node" style="background-color: ${color};"></div>
            <div class="remote-marker-ip-label">${dstIP}</div>
          `,
          iconSize: [120, 32],
          iconAnchor: [60, 5] // 60 is center horizontally, 5 is center of 10px circle
        });

        const marker = L.marker([dLat, dLon], { icon: markerIcon })
          .addTo(this.map)
          .bindTooltip(`
            <div class="text-xs font-mono space-y-1">
              <div class="flex items-center justify-between border-b border-cyan-500/30 pb-1 mb-1">
                <span class="font-bold text-cyan-300 text-sm tracking-wide">${dstIP}</span>
                <span class="text-[11px] text-slate-300 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-700">:${conn.destination.port || ''}</span>
              </div>
              <div class="text-[11px] text-slate-100 font-sans flex items-center">
                <span class="mr-1 text-cyan-400">📍</span>
                <span class="font-medium">${dstGeo.city || 'Unknown'}, ${dstGeo.country || ''}</span>
              </div>
              <div class="text-[10px] text-slate-400">
                <span class="text-slate-500">ISP:</span> <span class="text-slate-300">${dstGeo.isp || 'N/A'}</span>
              </div>
              <div class="text-[10px] text-slate-400 flex items-center justify-between pt-0.5">
                <span>Proc: <span class="text-emerald-400 font-bold">${conn.process}</span></span>
                <span class="px-1.5 py-0.2 bg-cyan-950 text-cyan-300 rounded border border-cyan-800 text-[9px] font-bold">${conn.protocol}</span>
              </div>
              <div class="text-[9px] text-cyan-400/80 pt-1 border-t border-slate-800 italic">
                ⚡ Click node to open deep inspector
              </div>
            </div>
          `, { direction: 'top', offset: [0, -8], className: 'cyber-tooltip', pane: 'topTooltipPane' });

        marker.on('click', () => {
          this.selectedArcId = conn.id;
          this.onSelectIP(dstIP, conn);
        });

        this.remoteMarkers.set(dstIP, marker);
      }
    });

    // Remove markers that are no longer active in this filtered set
    for (const [ip, marker] of this.remoteMarkers.entries()) {
      if (!currentIPs.has(ip)) {
        this.map.removeLayer(marker);
        this.remoteMarkers.delete(ip);
      }
    }

    this.activeArcs = newArcs;
    this.drawArcs();
  }

  handleMapMouseMove(e) {
    if (!this.activeArcs || this.activeArcs.length === 0) return;
    const mx = e.containerPoint.x;
    const my = e.containerPoint.y;

    let closestArc = null;
    let closestDist = 12; // 12px hit test radius

    for (const arc of this.activeArcs) {
      if (!arc.renderedPoints) continue;
      const { sx, sy, cx, cy, dx, dy } = arc.renderedPoints;
      const dist = this.getDistToCurve(mx, my, sx, sy, cx, cy, dx, dy);
      if (dist < closestDist) {
        closestDist = dist;
        closestArc = arc;
      }
    }

    if (closestArc !== this.hoveredArc) {
      this.hoveredArc = closestArc;
      this.container.style.cursor = closestArc ? 'pointer' : '';
      this.drawArcs();
    }
  }

  handleMapClick(e) {
    if (this.hoveredArc) {
      const arc = this.hoveredArc;
      this.selectedArcId = arc.id;
      this.drawArcs();

      if (this.onSelectIP && arc.dstIP) {
        this.onSelectIP(arc.dstIP, arc.connContext);
      }
      if (window.AegisUI) {
        window.AegisUI.showToast(`Selected Link: ${arc.protocol} → ${arc.dstIP} [${arc.process}]`, 'info');
      }
    }
  }

  getDistToCurve(mx, my, sx, sy, cx, cy, dx, dy) {
    let minDist = Infinity;
    for (let i = 0; i <= 12; i++) {
      const t = i / 12;
      const u = 1 - t;
      const px = u * u * sx + 2 * u * t * cx + t * t * dx;
      const py = u * u * sy + 2 * u * t * cy + t * t * dy;
      const d = Math.hypot(mx - px, my - py);
      if (d < minDist) minDist = d;
    }
    return minDist;
  }

  drawArcs() {
    if (!this.ctx || !this.map) return;

    const rect = this.container.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    this.ctx.clearRect(0, 0, rect.width, rect.height);

    const now = performance.now();

    this.activeArcs.forEach(arc => {
      // Project lat/lng to container pixel coordinates
      const srcPoint = this.map.latLngToContainerPoint([arc.sLat, arc.sLon]);
      const dstPoint = this.map.latLngToContainerPoint([arc.dLat, arc.dLon]);

      const sx = srcPoint.x;
      const sy = srcPoint.y;
      const dx = dstPoint.x;
      const dy = dstPoint.y;

      // Calculate control point for curved arc
      const mx = (sx + dx) / 2;
      const my = (sy + dy) / 2;
      const dist = Math.hypot(dx - sx, dy - sy);
      
      const arcHeight = Math.min(120, dist * 0.25);
      const angle = Math.atan2(dy - sy, dx - sx) - Math.PI / 2;
      const cx = mx + Math.cos(angle) * arcHeight;
      const cy = my + Math.sin(angle) * arcHeight;

      // Store rendered curve geometry for hit-testing and selection
      arc.renderedPoints = { sx, sy, cx, cy, dx, dy };

      const isSelected = this.selectedArcId === arc.id;
      const isHovered = this.hoveredArc === arc;

      // Draw Connection Arc (Softer/dimmer default, highlighted when hovered/selected)
      if (isSelected || isHovered) {
        // Selection glowing halo
        this.ctx.beginPath();
        this.ctx.moveTo(sx, sy);
        this.ctx.quadraticCurveTo(cx, cy, dx, dy);
        this.ctx.strokeStyle = '#00f3ff';
        this.ctx.globalAlpha = 0.55;
        this.ctx.lineWidth = 5.0;
        this.ctx.stroke();

        // Selection solid line
        this.ctx.beginPath();
        this.ctx.moveTo(sx, sy);
        this.ctx.quadraticCurveTo(cx, cy, dx, dy);
        this.ctx.strokeStyle = '#ffffff';
        this.ctx.globalAlpha = 1.0;
        this.ctx.lineWidth = 2.2;
        this.ctx.stroke();
      } else {
        // Normal arc: softer, refined cyber look (dimmer but visible)
        this.ctx.beginPath();
        this.ctx.moveTo(sx, sy);
        this.ctx.quadraticCurveTo(cx, cy, dx, dy);
        this.ctx.strokeStyle = arc.color;
        this.ctx.globalAlpha = 0.15;
        this.ctx.lineWidth = 2.8;
        this.ctx.stroke();

        this.ctx.beginPath();
        this.ctx.moveTo(sx, sy);
        this.ctx.quadraticCurveTo(cx, cy, dx, dy);
        this.ctx.strokeStyle = arc.color;
        this.ctx.globalAlpha = 0.45;
        this.ctx.lineWidth = 1.3;
        this.ctx.stroke();
      }

      // Subtle, clean destination anchor dot (no glowing highlight)
      this.ctx.beginPath();
      this.ctx.arc(dx, dy, 2.5, 0, Math.PI * 2);
      this.ctx.fillStyle = arc.color;
      this.ctx.globalAlpha = 0.75;
      this.ctx.shadowBlur = 0;
      this.ctx.fill();

      // Animate flowing packet particle along Bezier curve
      const t = (now * arc.speed + arc.offset) % 1.0;
      const oneMinusT = 1.0 - t;
      const px = oneMinusT * oneMinusT * sx + 2 * oneMinusT * t * cx + t * t * dx;
      const py = oneMinusT * oneMinusT * sy + 2 * oneMinusT * t * cy + t * t * dy;

      // Draw glowing packet particle
      this.ctx.globalAlpha = 1.0;
      this.ctx.shadowBlur = 10;
      this.ctx.shadowColor = arc.color;
      this.ctx.fillStyle = isSelected ? '#00f3ff' : '#ffffff';

      this.ctx.beginPath();
      this.ctx.arc(px, py, 3.2, 0, Math.PI * 2);
      this.ctx.fill();

      this.ctx.shadowBlur = 0;
    });

    this.ctx.globalAlpha = 1.0;
  }

  startAnimationLoop() {
    const loop = () => {
      this.drawArcs();
      this.animationFrameId = requestAnimationFrame(loop);
    };
    this.animationFrameId = requestAnimationFrame(loop);
  }

  flyToCoordinates(lat, lon, zoom = 6) {
    if (this.map && typeof lat === 'number' && typeof lon === 'number') {
      this.map.flyTo([lat, lon], zoom, { duration: 1.2 });
    }
  }

  destroy() {
    if (this.animationFrameId) {
      cancelAnimationFrame(this.animationFrameId);
    }
    if (this.map) {
      this.map.remove();
    }
  }
}

window.AegisMap = AegisMap;
