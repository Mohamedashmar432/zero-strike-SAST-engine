// ZS-TS-053: postMessage with a wildcard targetOrigin on a chained receiver
const payload: string = "t";
frame.contentWindow.postMessage(payload, '*');
