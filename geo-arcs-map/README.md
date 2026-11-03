# GeoArcsMap 🌐⚡

> **Zero-API-Key interactive world map with animated curved quadratic Bezier packet arcs, host stations, and destination anchor nodes.**  
> Built for SOC dashboards, real-time network monitors, threat visualizers, flight paths, and logistics tracking.

![GeoArcsMap](https://img.shields.io/badge/License-MIT-blue.svg)
![Zero API Key](https://img.shields.io/badge/API--Key-0%20(100%25%20Offline)-brightgreen.svg)
![Leaflet](https://img.shields.io/badge/Leaflet-Compatible-cyan.svg)

---

## ✨ Features

- 🛡️ **Zero API Key Architecture:** Bundled 173 KB offline GeoJSON vector basemap + automatic OpenStreetMap Inverted Dark fallback.
- ⚡ **Curved Quadratic Bezier Arcs:** Smooth mathematical curve rendering with flowing, glowing packet particles.
- 🎯 **Hit-Testing & Selection:** Mouse hover detection over arcs, selection halos, pointer cursor adjustments, and click callbacks.
- 📍 **Anchor Points & Nodes:** Local host station with pulsing radar rings, remote destination node markers with IP pills and custom tooltips.
- 📦 **Universal Integration:** Works with Vanilla HTML/JS, React, Vue, Svelte, Electron, and Python WebView.
- 🤖 **AI-Agent Ready:** Includes a dedicated [`AGENT_GUIDE.md`](./AGENT_GUIDE.md) enabling any AI coding agent to integrate it into a new project in minutes.

---

## 🚀 Quick Start

### 1. Include Assets

```html
<!-- Leaflet.js -->
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>

<!-- GeoArcsMap -->
<link rel="stylesheet" href="./dist/geo-arcs-map.css">
<script src="./src/data/world-data.js"></script>
<script src="./dist/geo-arcs-map.js"></script>
```

### 2. Instantiate & Add Data

```html
<div id="map" style="width: 100%; height: 600px;"></div>

<script>
  // 1. Initialize Map
  const map = new GeoArcsMap('map', {
    center: [25, 10],
    zoom: 2.2,
    hostLocation: {
      lat: 37.7749,
      lon: -122.4194,
      label: 'Main Host Station'
    }
  });

  // 2. Set Destination Nodes (Points)
  map.setNodes([
    { id: 'london', lat: 51.5074, lon: -0.1278, label: 'London Node', color: '#00ff88' },
    { id: 'tokyo', lat: 35.6762, lon: 139.6503, label: 'Tokyo Node', color: '#38bdf8' }
  ]);

  // 3. Set Connection Arcs (Links)
  map.setLinks([
    { id: 'l1', source: { lat: 37.7749, lon: -122.4194 }, target: { lat: 51.5074, lon: -0.1278 }, color: '#00ff88' },
    { id: 'l2', source: { lat: 37.7749, lon: -122.4194 }, target: { lat: 35.6762, lon: 139.6503 }, color: '#38bdf8' }
  ]);
</script>
```

---

## 🎮 Interactive Demo

Open [`examples/demo.html`](./examples/demo.html) directly in any modern web browser to explore:
- Interactive simulation of live worldwide links and points.
- Instant toggling between offline vector map and dark inverted OSM tiles.
- Camera controls (`flyTo` San Francisco, London, Tokyo, Reset).
- Telemetry HUD with node and link inspection.

---

## 🛠️ Framework Examples

- **React:** See [`examples/react-example.jsx`](./examples/react-example.jsx)
- **Vue 3:** See [`examples/vue-example.vue`](./examples/vue-example.vue)
- **AI Agents:** See [`AGENT_GUIDE.md`](./AGENT_GUIDE.md) for full data models and technical schemas.

---

## 📄 License

MIT © AegisNet / Antigravity Team

