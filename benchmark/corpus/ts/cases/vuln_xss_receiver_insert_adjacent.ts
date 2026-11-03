// ZS-TS-045: insertAdjacentHTML on an arbitrary receiver (not only `el`) with DOM-sourced markup
const h: string = location.hash;
card.insertAdjacentHTML('beforeend', h);
