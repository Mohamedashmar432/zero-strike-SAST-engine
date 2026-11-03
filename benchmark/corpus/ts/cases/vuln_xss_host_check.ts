declare function go(u: string): void;

export function redirect(u: string, redirectUrl: string): void {
  if (new URL(u).hostname.endsWith('example.com')) {
    go(u);
  }
  if (redirectUrl.startsWith('https://example.com')) {
    go(redirectUrl);
  }
}
