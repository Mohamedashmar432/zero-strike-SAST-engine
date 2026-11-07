import { DomSanitizer } from '@angular/platform-browser'

export class VulnBypassComponent {
  constructor (private sanitizer: DomSanitizer) {}
  load (value: string) {
    this.description = this.sanitizer.bypassSecurityTrustHtml(value)
  }
}
