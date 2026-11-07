// ZS-JS-178: AJAX reply rendered with .html()
$.get('/x', function (response) {
  $('#out').html(response);
});
