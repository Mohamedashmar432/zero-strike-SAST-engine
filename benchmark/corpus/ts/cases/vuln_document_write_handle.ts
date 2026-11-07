// ZS-TS-171: document.write on a window handle
function show(userData) {
  window.open('', '_blank')?.document.write(userData);
}
