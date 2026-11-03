<template>
  <div ref="mapContainer" class="cyber-map-wrapper"></div>
</template>

<script>
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { GeoArcsMap } from 'geo-arcs-map';
import 'geo-arcs-map/dist/geo-arcs-map.css';
import worldGeoJson from 'geo-arcs-map/dist/world.geojson';

export default {
  name: 'CyberWorldMap',
  props: {
    connections: {
      type: Array,
      default: () => []
    },
    hostLocation: {
      type: Object,
      default: () => ({ lat: 37.7749, lon: -122.4194, label: 'Host Station' })
    }
  },
  data() {
    return {
      mapInstance: null
    };
  },
  mounted() {
    this.mapInstance = new GeoArcsMap(this.$refs.mapContainer, {
      leaflet: L,
      geoJsonData: worldGeoJson,
      basemapMode: 'vector',
      hostLocation: this.hostLocation,
      onNodeClick: (node) => this.$emit('select-node', node),
      onLinkClick: (link) => this.$emit('select-link', link)
    });

    if (this.connections.length > 0) {
      this.mapInstance.updateConnections(this.connections, this.hostLocation);
    }
  },
  watch: {
    connections: {
      deep: true,
      handler(newVal) {
        if (this.mapInstance) {
          this.mapInstance.updateConnections(newVal, this.hostLocation);
        }
      }
    }
  },
  beforeUnmount() {
    if (this.mapInstance) {
      this.mapInstance.destroy();
    }
  }
};
</script>

<style scoped>
.cyber-map-wrapper {
  width: 100%;
  height: 600px;
  position: relative;
}
</style>

