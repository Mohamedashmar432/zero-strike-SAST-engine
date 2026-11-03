// Constant URLs, and a helper whose parameter is not a real untrusted source.
const link = document.getElementById('continue');
link.setAttribute('href', '/home');
function setLink(el, url) {
  el.setAttribute('href', url);
}
setLink(link, '/dashboard');
