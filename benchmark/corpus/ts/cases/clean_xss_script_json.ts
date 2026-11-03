declare function serialize(v: object): string;

export function page(res: any, state: object): void {
  res.send(`<html><body><script>window.__INITIAL_STATE__=${JSON.stringify(state).replace(/</g, '\\u003c')}</script></body></html>`);
}

export function page2(res: any, state: object): void {
  res.send(`<html><body><script>window.__INITIAL_STATE__=${serialize(state)}</script></body></html>`);
}
