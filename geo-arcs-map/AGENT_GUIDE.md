# AGENT INTEGRATION GUIDE: GeoArcsMap

> **Target Audience:** AI Coding Agents (Antigravity, Cursor, Copilot, Claude, Gemini, ChatGPT) & Developers.  
> **Package Purpose:** Drop-in, Zero-API-Key interactive world map with animated curved quadratic Bezier packet arcs, host stations, and destination anchor nodes.

---

## 1. Quick Capabilities Overview

- **Zero API Key Requirement:** Works 100% offline using the bundled vector GeoJSON (`world.geojson`) or falls back seamlessly to OpenStreetMap Inverted Dark Tiles.
- **Curved Animated Arcs (Links):** Quadratic Bezier calculations with glowing packet particle flow and hit-testing (hover detection, selection halo, click callbacks).
- **Interactive Anchor Points (Nodes):** Pulsing host station indicator, destination node circles with custom protocol colors, IP pill labels, and cyber tooltips.
- **Universal Compatibility:** Vanilla HTML/JS, React, Vue, Svelte, Electron, Python WebView / Desktop apps.

---

## 2. Package Directory Layout

```text
geo-arcs-map/
├── package.json               # NPM metadata & entry points
├── README.md                  # Human-readable documentation
├── AGENT_GUIDE.md             # This agent-oriented technical guide
├── dist/                      # Production-ready pre-built assets
│   ├── geo-arcs-map.js        # Universal UMD bundle (window.GeoArcsMap)
│   ├── geo-arcs-map.css       # Clean styling (markers, pins, canvas, tooltips)
│   └── world.geojson          # Standalone 173 KB offline world polygons
├── src/
│   ├── index.js               # UMD source
│   ├── index.esm.js           # Modern ES Module export (for Vite/Webpack/Rollup)
│   ├── geo-arcs-map.css       # Source CSS
│   └── data/
│       ├── world.geojson      # Raw GeoJSON
│       └── world-data.js      # Bundled window.WORLD_GEOJSON variable
└── examples/
    ├── demo.html              # Standalone runnable demo with simulation controls
    ├── react-example.jsx      # Copy-paste React / Next.js component
    └── vue-example.vue        # Copy-paste Vue 3 / Nuxt component
```

---

## 3. Quickest 2-Minute Setup

### Option A: Pure HTML / Vanilla JavaScript
```html
<!-- 1. Leaflet Core (CDN or Local) -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

<!-- 2. GeoArcsMap Styles, Bundled Vector Data & Engine -->
<link rel="stylesheet" href="./path/to/geo-arcs-map/dist/geo-arcs-map.css">
<script src="./path/to/geo-arcs-map/src/data/world-data.js"></script>
<script src="./path/to/geo-arcs-map/dist/geo-arcs-map.js"></script>

<!-- 3. Container Element -->
<div id="mapContainer" style="width: 100%; height: 600px;"></div>

<script>
  // 4. Instantiate
  const map = new GeoArcsMap('mapContainer', {
    center: [25, 10],
    zoom: 2.2,
    basemapMode: 'vector', // 'vector' (offline) or 'osm' (dark tiles)
    hostLocation: { lat: 37.7749, lon: -122.4194, label: 'Main Station' }
  });

  // 5. Add Points (Nodes)
  map.setNodes([
    { id: 'london', lat: 51.5074, lon: -0.1278, label: 'London Node', color: '#00ff88' },
    { id: 'tokyo', lat: 35.6762, lon: 139.6503, label: 'Tokyo Node', color: '#38bdf8' }
  ]);

  // 6. Add Links (Animated curved Bezier arcs)
  map.setLinks([
    { id: 'link-1', source: { lat: 37.7749, lon: -122.4194 }, target: { lat: 51.5074, lon: -0.1278 }, color: '#00ff88' },
    { id: 'link-2', source: { lat: 37.7749, lon: -122.4194 }, target: { lat: 35.6762, lon: 139.6503 }, color: '#38bdf8' }
  ]);
</script>
```

---

## 4. API Reference for the Agent

### Constructor Options
```javascript
new GeoArcsMap(containerElementOrId, {
  leaflet: L,                 // Optional: pass Leaflet instance if using bundlers
  center: [25, 10],          // Initial map center [lat, lon]
  zoom: 2.2,                 // Initial zoom level
  minZoom: 1.5,
  maxZoom: 14,
  basemapMode: 'vector',     // 'vector' | 'osm' | 'none'
  geoJsonData: null,         // Object | URL string | fallback to window.WORLD_GEOJSON
  hostLocation: null,        // { lat, lon, city, country, label }
  arcHeightFactor: 0.25,     // Arc curvature multiplier (default 0.25)
  maxArcHeight: 120,         // Max curve height in px
  packetSize: 3.2,           // Particle radius in px
  onNodeClick: (node) => {}, // Callback when a node is clicked
  onLinkClick: (link) => {}, // Callback when a curved arc is clicked
  onSelectIP: (ip, data) =>{}// Convenience callback for SOC/network applications
});
```

### Core Methods

| Method | Signature | Description |
|---|---|---|
| `setHostLocation(loc)` | `loc: { lat, lon, label, city, country }` | Sets/updates host station with glowing radar pulse. |
| `addNode(node)` | `node: { id, lat, lon, label, color, tooltipHtml, data }` | Adds or updates a single node. |
| `setNodes(nodesArray)` | `nodesArray: Array<Node>` | Replaces all nodes (diffs and cleans up removed nodes). |
| `removeNode(id)` | `id: string` | Removes node by ID. |
| `clearNodes()` | *none* | Removes all nodes. |
| `addLink(link)` | `link: { id, source, target, color, speed, offset, data }` | Adds or updates a single Bezier animated arc. |
| `setLinks(linksArray)` | `linksArray: Array<Link>` | Replaces all animated arcs. |
| `removeLink(id)` | `id: string` | Removes link by ID. |
| `clearLinks()` | *none* | Removes all arcs. |
| `updateConnections(conns, hostLoc)` | `conns: Array<Connection>, hostLoc: Object` | High-level batch ingestion for network/threat logs. |
| `toggleBasemapMode()` | *none* | Toggles between offline vector polygons and dark OSM tiles. |
| `flyTo(lat, lon, zoom)` | `lat, lon, zoom = 6` | Smooth camera pan & zoom animation. |
| `resize()` | *none* | Forces canvas & map dimension recalculation. |
| `destroy()` | *none* | Stops animation loop, cleans event listeners and DOM elements. |

---

## 5. High-Level Connection Schema (SOC / Live Network Data)

If your project receives live network sockets, pass them directly to `updateConnections()`:

```javascript
map.updateConnections([
  {
    id: "socket-1",
    protocol: "HTTPS",         // Determines color (HTTPS/HTTP: emerald, DNS: cyan, SSH: amber, etc.)
    process: "chrome.exe",
    destination: {
      ip: "142.250.190.46",
      port: 443,
      geo: { lat: 51.5074, lon: -0.1278, city: "London", country: "GB", isp: "Google LLC" }
    }
  }
], { lat: 37.7749, lon: -122.4194, label: "Local Station" });
```

---

## 6. Agent Implementation Advice

1. **Leaflet Dependency:** Ensure `leaflet` CSS & JS are present in the host project (`npm install leaflet` or `<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>`).
2. **Container Dimensions:** The map container MUST have a non-zero explicit width and height (e.g., `height: 600px` or `height: 100vh`).
3. **Canvas Hit-Testing:** The canvas overlay is `pointer-events: none`, but the engine binds Leaflet mousemove and click handlers to perform mathematical quadratic Bezier distance tests (`<= 12px`).
4. **Theme Customization:** Protocol colors, line widths, and tooltip styles can be modified via `src/geo-arcs-map.css`.

