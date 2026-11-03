export function listen(out: HTMLElement): void {
  window.addEventListener('message', (e: MessageEvent) => {
    out.textContent = String(e.data);
  });
}
