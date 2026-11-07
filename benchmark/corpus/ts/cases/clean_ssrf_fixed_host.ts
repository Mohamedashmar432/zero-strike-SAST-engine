// True negative: https.get to a fixed host that varies only an id, and a
// helper that takes the URL as a plain parameter (see ZS-JS-035).
import https from "https";

export function loadItem(req: any): void {
  const id = req.query.id;
  https.get(`https://api.service.invalid/v1/items/${id}`);
}

export function fetchPage(url: string): void {
  https.get(url);
}
