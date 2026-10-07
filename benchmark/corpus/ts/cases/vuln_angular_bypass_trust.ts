import { Component } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Component({ selector: 'app-post', template: '<div [innerHTML]="html"></div>' })
export class PostComponent {
  html: any;
  constructor(private sanitizer: DomSanitizer) {}
  render(userHtml: string) {
    this.html = this.sanitizer.bypassSecurityTrustHtml(userHtml);
  }
}
