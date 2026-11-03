// An on* attribute is compiled as script; here its value comes from the URL.
const code = location.hash.slice(1);
const btn = document.getElementById('go');
btn.setAttribute('onclick', code);
