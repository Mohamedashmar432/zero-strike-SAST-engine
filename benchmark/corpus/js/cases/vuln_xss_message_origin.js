// message listener trusts data from any origin.
const out = document.getElementById('out');
window.addEventListener('message', (e) => {
  out.textContent = String(e.data);
});
