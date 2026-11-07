// ZS-JS-179: error text exposed to the view
function onError(err, req, res, next) {
  res.locals.message = err.message;
  res.status(500);
}
