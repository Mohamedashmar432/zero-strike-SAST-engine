export function link(el: HTMLElement, u: string): void {
  el.setAttribute('href', u);
}

export function home(a: HTMLElement): void {
  a.setAttribute('href', '/home');
}
