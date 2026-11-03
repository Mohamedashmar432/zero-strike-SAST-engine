// ZS-JS-047: insertAdjacentHTML on an arbitrary receiver (not only `el`) with DOM-sourced markup
const h = location.hash;
card.insertAdjacentHTML('beforeend', h);
