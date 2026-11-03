// Unsafe HTML parsing APIs fed with attacker-controlled markup.
const host = document.getElementById('widget');
const markup = location.hash.slice(1);
host.setHTMLUnsafe(markup);
const frag = document.createRange().createContextualFragment(markup);
host.appendChild(frag);
