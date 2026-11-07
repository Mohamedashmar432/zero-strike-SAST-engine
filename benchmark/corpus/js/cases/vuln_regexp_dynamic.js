// ZS-JS-180: pattern built from a variable
function find(search) {
  return new RegExp('^log: ' + search);
}
