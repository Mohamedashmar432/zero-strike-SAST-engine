// ZS-JS-003: document.write() with a tainted argument (source: req.query)
let userInput = req.query.q;
document.write(userInput);
