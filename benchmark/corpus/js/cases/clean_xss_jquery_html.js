// Constant markup and the .html() getter are both safe.
$('#results').html('<i>loading</i>');
const previous = $('#results').html();
console.log(previous);
