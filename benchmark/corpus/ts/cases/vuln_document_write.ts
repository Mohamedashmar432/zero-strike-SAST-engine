// ZS-TS-003: document.write() with a tainted argument (source: req.query)
let userInput: string = req.query.q;
document.write(userInput);
