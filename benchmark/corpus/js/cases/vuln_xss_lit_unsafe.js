// Lit unsafeHTML directive rendering a dynamic value.
import { LitElement, html } from 'lit';
import { unsafeHTML } from 'lit/directives/unsafe-html.js';

class Article extends LitElement {
  render() {
    return html`<section>${unsafeHTML(this.content)}</section>`;
  }
}
customElements.define('x-article', Article);
