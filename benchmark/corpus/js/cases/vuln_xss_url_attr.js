// URL-bearing attributes set from a query-string value.
const next = new URLSearchParams(location.search).get('next');
const link = document.getElementById('continue');
link.setAttribute('href', next);
const icon = document.getElementById('icon');
icon.setAttributeNS('http://www.w3.org/1999/xlink', 'xlink:href', next);
