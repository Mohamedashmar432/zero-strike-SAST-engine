// jQuery .html() setter with a value read from the query string.
const q = new URLSearchParams(location.search).get('q');
$('#results').html(q);
