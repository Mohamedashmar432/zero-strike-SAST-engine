// Browser code (frontend/ source root, Angular module): console output is the
// user's own devtools, so log forging (ZS-TS-081) does not apply even to a
// real browser source such as location.search.
import { Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class BasketService {
  load(): void {
    const q = window.location.search;
    console.log(q);
  }
}
