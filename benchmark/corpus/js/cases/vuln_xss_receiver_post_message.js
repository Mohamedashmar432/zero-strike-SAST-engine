// ZS-JS-055: postMessage with a wildcard targetOrigin on a chained receiver
const payload = "t";
frame.contentWindow.postMessage(payload, '*');
