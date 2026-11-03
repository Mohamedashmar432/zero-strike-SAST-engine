// The handler verifies the sender's origin; other targets are not window messages.
const out = document.getElementById('out');
window.addEventListener('message', (e) => {
  if (e.origin !== 'https://app.example.com') return;
  out.textContent = String(e.data);
});
const socket = new WebSocket('wss://api.example.com/feed');
socket.addEventListener('message', (ev) => {
  out.textContent = String(ev.data);
});
