import { Component } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Component({ selector: 'app-logo', template: '<div [innerHTML]="html"></div>' })
export class LogoComponent {
  html: any;
  constructor(private sanitizer: DomSanitizer) {}
  render() {
    this.html = this.sanitizer.bypassSecurityTrustHtml('<b>static</b>');
  }
}
