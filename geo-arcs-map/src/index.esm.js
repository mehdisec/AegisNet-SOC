/**
 * GeoArcsMap - Modern ES Module Export
 */
import L from 'leaflet';
import './geo-arcs-map.css';

// Default color palette
export const DEFAULT_COLORS = {
  host: '#00f3ff',
  defaultLink: '#00f3ff',
  http: '#00ff88',
  https: '#00ff88',
  dns: '#38bdf8',
  ssh: '#ffaa00',
  rdp: '#ffaa00',
  alert: '#f43f5e',
  background: '#07090e',
  countryFill: '#0b1322',
  countryBorder: '#00f3ff'
};

export class GeoArcsMap {
  /**
   * @param {string|HTMLElement} container - DOM ID or container element
   * @param {Object} options - Configuration options
   */
  constructor(container, options = {}) {
    this.container = typeof container === 'string' ? document.getElementById(container) : container;
    if (!this.container) {
      throw new Error('[GeoArcsMap] Target container not found: ' + container);
    }

    this.container.classList.add('geo-arcs-container');
    this.L = options.leaflet || (typeof window !== 'undefined' ? window.L : null) || L;
    if (!this.L) {
      throw new Error('[GeoArcsMap] Leaflet.js (L) is required.');
    }

    this.options = Object.assign({
      center: [25, 10],
      zoom: 2.2,
      minZoom: 1.5,
      maxZoom: 14,
      basemapMode: 'vector', // 'vector' | 'osm' | 'none'
      geoJsonData: null,
      theme: 'cyber',
      arcHeightFactor: 0.25,
      maxArcHeight: 120,
      packetSize: 3.2,
      hitRadius: 12,
      onNodeClick: null,
      onLinkClick: null,
      onSelectIP: null,
      renderNodeTooltip: null,
      renderHostTooltip: null
    }, options);

    this.map = null;
    this.canvas = null;
    this.ctx = null;
    this.animationFrameId = null;

    this.geoJsonLayer = null;
    this.tileLayer = null;
    this.currentMode = this.options.basemapMode;

    this.hostLocation = null;
    this.hostMarker = null;

    this.nodes = new Map();
    this.activeArcs = [];
    this.hoveredArc = null;
    this.selectedArcId = null;

    this._initMap();
    this._initBasemap();
    this._initCanvasOverlay();
    this._bindInteractions();
    this._startAnimationLoop();

    if (options.hostLocation) {
      this.setHostLocation(options.hostLocation);
    }
  }

  _initMap() {
    const L = this.L;
    this.map = L.map(this.container, {
      center: this.options.center,
      zoom: this.options.zoom,
      minZoom: this.options.minZoom,
      maxZoom: this.options.maxZoom,
      zoomControl: true,
      worldCopyJump: true,
      attributionControl: false
    });

    if (this.map.zoomControl) {
      this.map.zoomControl.setPosition('bottomright');
    }

    this.map.createPane('topTooltipPane', this.container);
    const tooltipPane = this.map.getPane('topTooltipPane');
    if (tooltipPane) {
      tooltipPane.style.zIndex = '10000';
      tooltipPane.style.pointerEvents = 'none';
    }

    setTimeout(() => {
      if (this.map) this.map.invalidateSize();
    }, 250);
  }

  _initBasemap() {
    if (this.currentMode === 'vector') {
      this._loadVectorBasemap();
    } else if (this.currentMode === 'osm') {
      this.enableOsmTiles();
    }
  }

  _loadVectorBasemap() {
    if (this.options.geoJsonData && typeof this.options.geoJsonData === 'object') {
      this._renderGeoJson(this.options.geoJsonData);
      return;
    }

    if (typeof this.options.geoJsonData === 'string') {
      fetch(this.options.geoJsonData)
        .then(res => res.json())
        .then(data => this._renderGeoJson(data))
        .catch(err => {
          console.warn('[GeoArcsMap] Failed to fetch geoJsonData URL, fallback to OSM dark:', err);
          this.enableOsmTiles();
        });
      return;
    }

    if (typeof window !== 'undefined' && window.WORLD_GEOJSON) {
      this._renderGeoJson(window.WORLD_GEOJSON);
      return;
    }

    fetch('./world.geojson')
      .then(res => res.json())
      .then(data => this._renderGeoJson(data))
      .catch(() => {
        this.enableOsmTiles();
      });
  }

  _renderGeoJson(geoData) {
    if (this.geoJsonLayer && this.map) {
      this.map.removeLayer(this.geoJsonLayer);
    }

    const L = this.L;
    this.geoJsonLayer = L.geoJSON(geoData, {
      style: () => ({
        fillColor: DEFAULT_COLORS.countryFill,
        fillOpacity: 0.95,
        color: DEFAULT_COLORS.countryBorder,
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
      return 'osm';
    } else {
      this.enableVectorBasemap();
      this.currentMode = 'vector';
      return 'vector';
    }
  }

  enableOsmTiles() {
    if (this.geoJsonLayer && this.map) {
      this.map.removeLayer(this.geoJsonLayer);
    }
    if (!this.tileLayer) {
      const L = this.L;
      this.tileLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        subdomains: ['a', 'b', 'c'],
        maxZoom: 18,
        className: 'osm-dark-tiles'
      });
    }
    this.tileLayer.addTo(this.map);
    this.currentMode = 'osm';
  }

  enableVectorBasemap() {
    if (this.tileLayer && this.map) {
      this.map.removeLayer(this.tileLayer);
    }
    if (this.geoJsonLayer && this.map) {
      this.geoJsonLayer.addTo(this.map);
    } else {
      this._loadVectorBasemap();
    }
    this.currentMode = 'vector';
  }

  _initCanvasOverlay() {
    this.canvas = document.createElement('canvas');
    this.canvas.className = 'geo-arcs-canvas';
    this.canvas.id = 'arcCanvas';
    this.container.appendChild(this.canvas);
    this.ctx = this.canvas.getContext('2d');

    const resizeCanvas = () => {
      const rect = this.container.getBoundingClientRect();
      const dpr = (typeof window !== 'undefined' && window.devicePixelRatio) || 1;
      this.canvas.width = rect.width * dpr;
      this.canvas.height = rect.height * dpr;
      this.canvas.style.width = `${rect.width}px`;
      this.canvas.style.height = `${rect.height}px`;
      this.ctx.scale(dpr, dpr);
    };

    resizeCanvas();
    this._resizeHandler = resizeCanvas;
    if (typeof window !== 'undefined') {
      window.addEventListener('resize', this._resizeHandler);
    }

    this.map.on('move', () => this.drawArcs());
    this.map.on('zoom', () => this.drawArcs());
    this.map.on('resize', () => {
      resizeCanvas();
      this.drawArcs();
    });
  }

  _bindInteractions() {
    this.map.on('mousemove', (e) => this._handleMapMouseMove(e));
    this.map.on('click', (e) => this._handleMapClick(e));
  }

  _startAnimationLoop() {
    const loop = () => {
      this.drawArcs();
      this.animationFrameId = requestAnimationFrame(loop);
    };
    this.animationFrameId = requestAnimationFrame(loop);
  }

  setHostLocation(loc) {
    if (!loc || typeof loc.lat !== 'number' || typeof loc.lon !== 'number') return;
    this.hostLocation = loc;
    const L = this.L;

    if (this.hostMarker) {
      this.hostMarker.setLatLng([loc.lat, loc.lon]);
    } else {
      const hostIcon = L.divIcon({
        className: 'host-marker-wrapper',
        html: `<div class="host-marker-pin" title="${loc.label || 'Host Station'}"></div>`,
        iconSize: [24, 24],
        iconAnchor: [12, 12]
      });

      const tooltipHTML = this.options.renderHostTooltip
        ? this.options.renderHostTooltip(loc)
        : `
          <div style="font-size: 11px; font-family: monospace; padding: 4px;">
            <div style="font-weight: bold; color: #00f3ff; text-transform: uppercase; margin-bottom: 4px;">🛡️ ${loc.label || 'Host Station'}</div>
            <div style="color: #f1f5f9; font-weight: 500;">${loc.city || 'Local'}, ${loc.country || 'Host'}</div>
            <div style="color: #94a3b8; font-size: 10px; margin-top: 4px;">LAT: ${loc.lat.toFixed(4)}, LON: ${loc.lon.toFixed(4)}</div>
          </div>
        `;

      this.hostMarker = L.marker([loc.lat, loc.lon], { icon: hostIcon, zIndexOffset: 1000 })
        .addTo(this.map)
        .bindPopup(tooltipHTML);
    }
  }

  addNode(node) {
    if (!node || !node.id || typeof node.lat !== 'number' || typeof node.lon !== 'number') return;
    const L = this.L;
    const color = node.color || DEFAULT_COLORS.defaultLink;
    const label = node.label || node.id;

    const tooltipContent = node.tooltipHtml || (this.options.renderNodeTooltip
      ? this.options.renderNodeTooltip(node)
      : `
        <div style="font-size: 11px; font-family: monospace;">
          <div style="font-weight: bold; color: #00f3ff; margin-bottom: 2px;">${label}</div>
          <div style="color: #cbd5e1;">Lat: ${node.lat.toFixed(3)}, Lon: ${node.lon.toFixed(3)}</div>
        </div>
      `);

    if (this.nodes.has(node.id)) {
      const item = this.nodes.get(node.id);
      const marker = item.marker;
      const curPos = marker.getLatLng();
      if (Math.abs(curPos.lat - node.lat) > 0.001 || Math.abs(curPos.lng - node.lon) > 0.001) {
        marker.setLatLng([node.lat, node.lon]);
      }
      if (marker.getTooltip()) {
        marker.setTooltipContent(tooltipContent);
      }
      item.data = node;
    } else {
      const markerIcon = L.divIcon({
        className: 'remote-marker-wrapper',
        html: `
          <div class="remote-marker-node" style="background-color: ${color};"></div>
          <div class="remote-marker-ip-label">${label}</div>
        `,
        iconSize: [120, 32],
        iconAnchor: [60, 5],
        tooltipAnchor: [0, 0]
      });

      const marker = L.marker([node.lat, node.lon], { icon: markerIcon })
        .addTo(this.map)
        .bindTooltip(tooltipContent, {
          direction: 'auto',
          offset: [10, 0],
          className: 'cyber-tooltip',
          pane: 'topTooltipPane',
          opacity: 1.0
        });

      marker.on('click', () => {
        this.selectedArcId = node.id;
        if (this.options.onNodeClick) {
          this.options.onNodeClick(node);
        }
        if (this.options.onSelectIP) {
          this.options.onSelectIP(node.label || node.id, node.data || node);
        }
      });

      this.nodes.set(node.id, { marker, data: node });
    }
  }

  removeNode(id) {
    if (this.nodes.has(id)) {
      const { marker } = this.nodes.get(id);
      if (this.map && marker) {
        this.map.removeLayer(marker);
      }
      this.nodes.delete(id);
    }
  }

  setNodes(nodesArray) {
    const activeIds = new Set();
    (nodesArray || []).forEach(node => {
      if (!node || !node.id) return;
      activeIds.add(node.id);
      this.addNode(node);
    });

    for (const [id] of this.nodes.entries()) {
      if (!activeIds.has(id)) {
        this.removeNode(id);
      }
    }
  }

  clearNodes() {
    for (const [id] of this.nodes.entries()) {
      this.removeNode(id);
    }
  }

  addLink(link) {
    if (!link || !link.id) return;
    const sLat = link.source ? link.source.lat : (this.hostLocation ? this.hostLocation.lat : 0);
    const sLon = link.source ? link.source.lon : (this.hostLocation ? this.hostLocation.lon : 0);
    const dLat = link.target ? link.target.lat : 0;
    const dLon = link.target ? link.target.lon : 0;

    if (typeof dLat !== 'number' || typeof dLon !== 'number' || (dLat === 0 && dLon === 0)) return;

    const arc = {
      id: link.id,
      sLat, sLon,
      dLat, dLon,
      color: link.color || DEFAULT_COLORS.defaultLink,
      speed: link.speed || 0.00015,
      offset: typeof link.offset === 'number' ? link.offset : Math.random(),
      data: link.data || link,
      renderedPoints: null
    };

    const existingIdx = this.activeArcs.findIndex(a => a.id === link.id);
    if (existingIdx >= 0) {
      this.activeArcs[existingIdx] = arc;
    } else {
      this.activeArcs.push(arc);
    }
  }

  removeLink(id) {
    this.activeArcs = this.activeArcs.filter(a => a.id !== id);
  }

  setLinks(linksArray) {
    this.activeArcs = [];
    (linksArray || []).forEach((link, idx) => {
      if (!link) return;
      this.addLink(Object.assign({ offset: (idx * 0.17) % 1.0 }, link));
    });
    this.drawArcs();
  }

  clearLinks() {
    this.activeArcs = [];
    this.drawArcs();
  }

  updateConnections(connections, hostLoc) {
    if (hostLoc) {
      this.setHostLocation(hostLoc);
    }

    const activeNodes = [];
    const activeLinks = [];

    (connections || []).forEach((conn, index) => {
      if (!conn.destination || !conn.destination.geo) return;
      const dstGeo = conn.destination.geo;
      const dstIP = conn.destination.ip;
      if (!dstIP || dstGeo.is_private) return;

      const dLat = dstGeo.lat;
      const dLon = dstGeo.lon;
      if (typeof dLat !== 'number' || typeof dLon !== 'number' || (dLat === 0 && dLon === 0)) return;

      let color = DEFAULT_COLORS.defaultLink;
      const proto = (conn.protocol || '').toUpperCase();
      if (proto === 'HTTPS' || proto === 'HTTP') color = DEFAULT_COLORS.https;
      else if (proto === 'DNS') color = DEFAULT_COLORS.dns;
      else if (proto === 'SSH' || proto === 'RDP') color = DEFAULT_COLORS.ssh;
      else if (conn.status === 'SYN_SENT' || conn.status === 'TIME_WAIT') color = DEFAULT_COLORS.alert;

      const port = conn.destination.port ? `:${conn.destination.port}` : '';
      const city = dstGeo.city || 'Unknown';
      const country = dstGeo.country || '';
      const locationStr = country ? `${city}, ${country}` : city;
      const isp = dstGeo.isp || 'N/A';
      const proc = conn.process || 'Unknown';

      const tooltipHtml = `
        <div style="font-size: 11px; font-family: monospace; line-height: 1.4;">
          <div style="display: flex; justify-content: space-between; border-bottom: 1px solid rgba(0,243,255,0.3); padding-bottom: 3px; margin-bottom: 4px;">
            <span style="font-weight: bold; color: #00f3ff; font-size: 12px;">${dstIP}</span>
            <span style="color: #cbd5e1; background: #07090e; padding: 1px 4px; border-radius: 2px;">${port}</span>
          </div>
          <div style="color: #f1f5f9; display: flex; align-items: center; margin-bottom: 2px;">
            <span style="margin-right: 4px; color: #00f3ff;">📍</span>
            <span style="font-weight: 500;">${locationStr}</span>
          </div>
          <div style="color: #94a3b8; font-size: 10px;">
            <span style="color: #64748b;">ISP:</span> <span>${isp}</span>
          </div>
          <div style="color: #94a3b8; font-size: 10px; display: flex; justify-content: space-between; padding-top: 2px;">
            <span>Proc: <span style="color: #00ff88; font-weight: bold;">${proc}</span></span>
            <span style="background: rgba(0,243,255,0.1); color: #00f3ff; padding: 1px 4px; border: 1px solid rgba(0,243,255,0.4); border-radius: 2px; font-weight: bold; font-size: 9px;">${proto || 'TCP'}</span>
          </div>
        </div>
      `;

      activeNodes.push({
        id: dstIP,
        lat: dLat,
        lon: dLon,
        label: dstIP,
        color: color,
        tooltipHtml: tooltipHtml,
        data: conn
      });

      const sLat = (conn.source && conn.source.geo && typeof conn.source.geo.lat === 'number')
        ? conn.source.geo.lat
        : (this.hostLocation ? this.hostLocation.lat : 0);
      const sLon = (conn.source && conn.source.geo && typeof conn.source.geo.lon === 'number')
        ? conn.source.geo.lon
        : (this.hostLocation ? this.hostLocation.lon : 0);

      activeLinks.push({
        id: conn.id || `${dstIP}-${index}`,
        source: { lat: sLat, lon: sLon },
        target: { lat: dLat, lon: dLon },
        color: color,
        speed: 0.00012 + ((index % 4) * 0.00003),
        offset: (index * 0.17) % 1.0,
        data: conn
      });
    });

    this.setNodes(activeNodes);
    this.setLinks(activeLinks);
  }

  _handleMapMouseMove(e) {
    if (!this.activeArcs || this.activeArcs.length === 0) return;
    const mx = e.containerPoint.x;
    const my = e.containerPoint.y;

    let closestArc = null;
    let closestDist = this.options.hitRadius;

    for (const arc of this.activeArcs) {
      if (!arc.renderedPoints) continue;
      const { sx, sy, cx, cy, dx, dy } = arc.renderedPoints;
      const dist = this._getDistToCurve(mx, my, sx, sy, cx, cy, dx, dy);
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

  _handleMapClick(e) {
    if (this.hoveredArc) {
      const arc = this.hoveredArc;
      this.selectedArcId = arc.id;
      this.drawArcs();

      if (this.options.onLinkClick) {
        this.options.onLinkClick(arc);
      }
      if (this.options.onSelectIP && arc.data && arc.data.destination) {
        this.options.onSelectIP(arc.data.destination.ip, arc.data);
      }
    }
  }

  _getDistToCurve(mx, my, sx, sy, cx, cy, dx, dy) {
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
    this.ctx.clearRect(0, 0, rect.width, rect.height);
    const now = performance.now();

    this.activeArcs.forEach(arc => {
      const srcPoint = this.map.latLngToContainerPoint([arc.sLat, arc.sLon]);
      const dstPoint = this.map.latLngToContainerPoint([arc.dLat, arc.dLon]);

      const sx = srcPoint.x;
      const sy = srcPoint.y;
      const dx = dstPoint.x;
      const dy = dstPoint.y;

      const mx = (sx + dx) / 2;
      const my = (sy + dy) / 2;
      const dist = Math.hypot(dx - sx, dy - sy);

      const arcHeight = Math.min(this.options.maxArcHeight, dist * this.options.arcHeightFactor);
      const angle = Math.atan2(dy - sy, dx - sx) - Math.PI / 2;
      const cx = mx + Math.cos(angle) * arcHeight;
      const cy = my + Math.sin(angle) * arcHeight;

      arc.renderedPoints = { sx, sy, cx, cy, dx, dy };

      const isSelected = this.selectedArcId === arc.id;
      const isHovered = this.hoveredArc === arc;

      if (isSelected || isHovered) {
        this.ctx.beginPath();
        this.ctx.moveTo(sx, sy);
        this.ctx.quadraticCurveTo(cx, cy, dx, dy);
        this.ctx.strokeStyle = '#00f3ff';
        this.ctx.globalAlpha = 0.55;
        this.ctx.lineWidth = 5.0;
        this.ctx.stroke();

        this.ctx.beginPath();
        this.ctx.moveTo(sx, sy);
        this.ctx.quadraticCurveTo(cx, cy, dx, dy);
        this.ctx.strokeStyle = '#ffffff';
        this.ctx.globalAlpha = 1.0;
        this.ctx.lineWidth = 2.2;
        this.ctx.stroke();
      } else {
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

      this.ctx.beginPath();
      this.ctx.arc(dx, dy, 2.5, 0, Math.PI * 2);
      this.ctx.fillStyle = arc.color;
      this.ctx.globalAlpha = 0.75;
      this.ctx.shadowBlur = 0;
      this.ctx.fill();

      const t = (now * arc.speed + arc.offset) % 1.0;
      const u = 1.0 - t;
      const px = u * u * sx + 2 * u * t * cx + t * t * dx;
      const py = u * u * sy + 2 * u * t * cy + t * t * dy;

      this.ctx.globalAlpha = 1.0;
      this.ctx.shadowBlur = 10;
      this.ctx.shadowColor = arc.color;
      this.ctx.fillStyle = isSelected ? '#00f3ff' : '#ffffff';

      this.ctx.beginPath();
      this.ctx.arc(px, py, this.options.packetSize, 0, Math.PI * 2);
      this.ctx.fill();

      this.ctx.shadowBlur = 0;
    });

    this.ctx.globalAlpha = 1.0;
  }

  flyTo(lat, lon, zoom = 6) {
    if (this.map && typeof lat === 'number' && typeof lon === 'number') {
      this.map.flyTo([lat, lon], zoom, { duration: 1.2 });
    }
  }

  resize() {
    if (this._resizeHandler) {
      this._resizeHandler();
    }
    if (this.map) {
      this.map.invalidateSize();
    }
  }

  destroy() {
    if (this.animationFrameId) {
      cancelAnimationFrame(this.animationFrameId);
    }
    if (this._resizeHandler && typeof window !== 'undefined') {
      window.removeEventListener('resize', this._resizeHandler);
    }
    if (this.map) {
      this.map.remove();
      this.map = null;
    }
    if (this.canvas && this.canvas.parentNode) {
      this.canvas.parentNode.removeChild(this.canvas);
    }
    this.nodes.clear();
    this.activeArcs = [];
  }
}

export default GeoArcsMap;

