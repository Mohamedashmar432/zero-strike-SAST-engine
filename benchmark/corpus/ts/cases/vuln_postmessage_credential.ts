// ZS-TS-170: credential posted to every origin
function send(frame) {
  frame.postMessage(localStorage.getItem('session_token'), '*');
}
