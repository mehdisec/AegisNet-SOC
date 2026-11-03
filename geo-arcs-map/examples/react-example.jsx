import React, { useEffect, useRef } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { GeoArcsMap } from 'geo-arcs-map';
import 'geo-arcs-map/dist/geo-arcs-map.css';
import worldGeoJson from 'geo-arcs-map/dist/world.geojson';

export function CyberWorldMap({ connections = [], hostLocation, onSelectNode, onSelectLink }) {
  const containerRef = useRef(null);
  const mapInstanceRef = useRef(null);

  useEffect(() => {
    if (!containerRef.current) return;

    // Initialize map
    const map = new GeoArcsMap(containerRef.current, {
      leaflet: L,
      geoJsonData: worldGeoJson,
      basemapMode: 'vector',
      hostLocation: hostLocation || {
        lat: 37.7749,
        lon: -122.4194,
        label: 'Local Host Station'
      },
      onNodeClick: (node) => {
        if (onSelectNode) onSelectNode(node);
      },
      onLinkClick: (link) => {
        if (onSelectLink) onSelectLink(link);
      }
    });

    mapInstanceRef.current = map;

    return () => {
      map.destroy();
    };
  }, []);

  // Update dynamic links & nodes when connections prop changes
  useEffect(() => {
    if (mapInstanceRef.current && connections) {
      mapInstanceRef.current.updateConnections(connections, hostLocation);
    }
  }, [connections, hostLocation]);

  return (
    <div 
      ref={containerRef} 
      style={{ width: '100%', height: '600px', position: 'relative' }} 
    />
  );
}

export default CyberWorldMap;

