const XLINK = 'http://www.w3.org/1999/xlink';

export function link(a: HTMLElement, use: SVGElement): void {
  const u: string | null = new URLSearchParams(location.search).get('next');
  a.setAttribute('href', u as string);
  use.setAttributeNS(XLINK, 'xlink:href', u as string);
}
