// Constant markup passed to the unsafe parsing APIs is not attacker-controlled.
const host = document.getElementById('widget');
host.setHTMLUnsafe('<b>static</b>');
const frag = document.createRange().createContextualFragment('<i>static</i>');
host.appendChild(frag);
