export function wire(btn: HTMLElement): void {
  btn.setAttribute('onclick', 'toggle()');
  btn.setAttribute('title', location.hash);
}
