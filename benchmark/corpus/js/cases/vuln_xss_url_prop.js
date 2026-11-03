// href / action properties assigned from a query-string value.
const next = new URLSearchParams(location.search).get('next');
const anchor = document.getElementById('continue');
anchor.href = next;
const form = document.getElementById('login');
form.action = next;
