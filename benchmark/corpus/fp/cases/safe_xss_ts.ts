// Safe DOM output, TypeScript twin of safe_xss_js.js. Nothing here should be
// reported.
//
// The headline case is insertAdjacentHTML: the ONLY argument that reaches the
// HTML parser is argument 1. Argument 0 is the insertion position, a keyword
// the DOM validates against a fixed set of four values. Before ZS-TS-045 was
// pinned to index 1, a tainted position with constant markup was reported as
// DOM XSS even though no attacker-controlled byte is ever parsed.

type InsertPosition = 'beforebegin' | 'afterbegin' | 'beforeend' | 'afterend';

// Attacker picks WHERE the banner goes; the banner itself is a constant.
function renderBanner(req: any, el: HTMLElement): void {
  const position = req.query.placement as InsertPosition;
  el.insertAdjacentHTML(position, '<b>Welcome back</b>');
}

// Attacker-controlled text, inserted as text. insertAdjacentText escapes by
// construction, so this is the fix ZS-TS-045 recommends, not a finding.
function renderComment(req: any, el: HTMLElement): void {
  const comment: string = req.query.comment;
  el.insertAdjacentText('beforeend', comment);
}

// document.write and document.writeln stay broad on purpose (every argument
// is concatenated into the parser stream), so these must be safe by having no
// tainted argument at all rather than by position.
function renderFooter(): void {
  document.write('<footer>', '&copy; 2026', '</footer>');
  document.writeln('<hr>');
}
