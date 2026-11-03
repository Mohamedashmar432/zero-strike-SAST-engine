export function wire(btn: HTMLElement): void {
  const c: string = location.hash.slice(1);
  btn.setAttribute('onclick', c);
}
