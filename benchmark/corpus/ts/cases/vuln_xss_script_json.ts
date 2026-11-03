export function page(res: any, state: object): void {
  res.send(`<html><body><script>window.__INITIAL_STATE__=${JSON.stringify(state)}</script></body></html>`);
}
