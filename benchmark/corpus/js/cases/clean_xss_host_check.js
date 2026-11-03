// Anchored host/origin checks.
function go(target) {
  console.log("navigate", target);
}
function guard(rawUrl, redirectUrl, name) {
  if (new URL(rawUrl).hostname.endsWith('.example.com')) {
    go(rawUrl);
  }
  if (redirectUrl.startsWith('https://example.com/')) {
    go(redirectUrl);
  }
  return name.includes('example.com');
}
module.exports = { guard };
