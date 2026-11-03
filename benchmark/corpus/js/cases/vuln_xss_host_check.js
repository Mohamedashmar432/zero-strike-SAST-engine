// Incomplete host/origin checks: evil-example.com and example.com.evil.net pass.
function go(target) {
  console.log("navigate", target);
}
function guard(rawUrl, redirectUrl) {
  if (new URL(rawUrl).hostname.endsWith('example.com')) {
    go(rawUrl);
  }
  if (redirectUrl.startsWith('https://example.com')) {
    go(redirectUrl);
  }
}
module.exports = { guard };
