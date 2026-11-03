import { html } from 'lit';
import { unsafeHTML } from 'lit/directives/unsafe-html.js';

export function staticCard() {
  return html`<div>${unsafeHTML('<b>x</b>')}</div>`;
}

function unsafeSVG(s: string): string {
  return s;
}

export function local(s: string): string {
  return unsafeSVG(s);
}
