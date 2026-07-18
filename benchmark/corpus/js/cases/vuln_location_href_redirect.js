// ZS-JS-046: DOM open redirect — location.href assigned from location.search
function redirectToNext() {
  const target = location.search;
  location.href = target;
}
