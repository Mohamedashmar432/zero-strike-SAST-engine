// Constant handler text, and a tainted value in a non-URL, non-handler attribute.
const btn = document.getElementById('go');
btn.setAttribute('onclick', 'toggle()');
btn.setAttribute('title', 'Open the panel');
btn.setAttribute('aria-label', 'Go');
