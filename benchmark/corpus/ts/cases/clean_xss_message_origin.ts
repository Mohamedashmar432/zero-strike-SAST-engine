export function listen(out: HTMLElement, ws: WebSocket, h: EventListener): void {
  window.addEventListener('message', (e: MessageEvent) => {
    if (e.origin !== 'https://app.example.com') {
      return;
    }
    out.textContent = String(e.data);
  });
  ws.addEventListener('message', h);
}
