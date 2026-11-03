export function renderFromHash(host: HTMLElement): DocumentFragment {
  const h: string = location.hash.slice(1);
  host.setHTMLUnsafe(h);
  return document.createRange().createContextualFragment(h);
}
