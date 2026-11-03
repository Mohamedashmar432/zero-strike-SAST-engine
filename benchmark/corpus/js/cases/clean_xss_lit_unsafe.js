// Constant argument to the unsafeHTML directive.
import { LitElement, html } from 'lit';
import { unsafeHTML } from 'lit/directives/unsafe-html.js';

class Banner extends LitElement {
  render() {
    return html`<section>${unsafeHTML('<b>static</b>')}</section>`;
  }
}
customElements.define('x-banner', Banner);
