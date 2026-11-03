// A sanitizer on only part of the expression does not neutralise the DOM-sourced remainder
const clean: string = '<b>x</b>';
el.innerHTML = DOMPurify.sanitize(clean) + location.hash;
el.outerHTML = DOMPurify.sanitize(clean) + location.hash;
frame.srcdoc = DOMPurify.sanitize(clean) + location.hash;
