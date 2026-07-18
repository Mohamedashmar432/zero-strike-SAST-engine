// ZS-TS-044: DOM open redirect — location.href assigned from location.search
function redirectToNext() {
  const target: string = location.search;
  location.href = target;
}
