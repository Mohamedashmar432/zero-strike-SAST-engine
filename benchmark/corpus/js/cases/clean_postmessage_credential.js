function send(frame) {
  frame.postMessage(localStorage.getItem('session_token'), 'https://app.example.test');
}
