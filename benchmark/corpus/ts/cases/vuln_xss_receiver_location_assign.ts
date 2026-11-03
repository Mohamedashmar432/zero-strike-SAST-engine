// Location sinks reached through a window. receiver and bare location assignment
const raw: string = location.hash.slice(1);
window.location.assign(raw);
window.location.replace(raw);
window.location = raw;
document.location = raw;
