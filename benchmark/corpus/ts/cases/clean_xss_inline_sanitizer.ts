// Sanitizer wrapping the whole right-hand side: no finding on the assignment sinks
const raw: string = location.hash.slice(1);
el.innerHTML = DOMPurify.sanitize(raw);
el.innerHTML = sanitizeHtml(location.hash.slice(1));
el.outerHTML = filterXSS(raw);
frame.srcdoc = DOMPurify.sanitize(location.hash.slice(1));
window.location = '/home';
window.location.assign('/home');
card.insertAdjacentHTML('beforeend', '<b>static</b>');
frame.contentWindow.postMessage('hi', 'https://app.example.com');
worker.postMessage(msg, [buf]);
