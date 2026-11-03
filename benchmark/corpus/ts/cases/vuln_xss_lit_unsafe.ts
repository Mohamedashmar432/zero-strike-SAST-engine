import { html, LitElement } from 'lit';
import { unsafeHTML } from 'lit/directives/unsafe-html.js';

export class Card extends LitElement {
  content: string = '';
  render() {
    return html`<div>${unsafeHTML(this.content)}</div>`;
  }
}
