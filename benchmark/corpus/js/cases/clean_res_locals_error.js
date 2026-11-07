function onError(err, req, res, next) {
  res.locals.message = 'Something went wrong';
  res.status(500);
}
