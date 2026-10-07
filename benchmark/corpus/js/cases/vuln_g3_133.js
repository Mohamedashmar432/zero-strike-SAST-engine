// ZS-JS-133: CWE-22: uploaded file moved to a path built from the client file name
function upload(req, res) {
  const sampleFile = req.files.file;
  const filePath = __dirname + '/uploads/' + sampleFile.name;
  sampleFile.mv(filePath, function (err) {
    res.json('uploaded');
  });
}
