/* eslint-disable*/

console.log('hi');
const locations = JSON.parse(document.getElementById('map').dataset.locations);

mapboxgl.accessToken =
  'pk.eyJ1IjoibGVvem90IiwiYSI6ImNsNXhwZnM1MTA2NnozZHAyMjR6bGJoZHoifQ.G4DGGPpVIDVBVhs9XPEFjA';
var map = new mapboxgl.Map({
  container: 'map',
  style: 'mapbox://styles/mapbox/light-v10',
  scrollZoom: false,
});

const bounds = new mapboxgl.LngLatBounds();

locations.forEach((loc) => {
  const el = document.createElement('div');
  el.className = 'marker';

  new mapboxgl.Marker({
    element: el,
    anchor: 'bottom',
  })
    .setLngLat(loc.coordinates)
    .addTo(map);

  new mapboxgl.Popup({
    offset: 30,
  })
    .setLngLat(loc.coordinates)
    .setHTML(`<p>Day ${loc.day}: ${loc.description}</p>`)
    .addTo(map);
  bounds.extend(loc.coordinates);
});

map.fitBounds(bounds, {
  padding: {
    top: 200,
    bottom: 200,
    left: 100,
    right: 100,
  },
});