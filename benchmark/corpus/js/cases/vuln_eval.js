// ZS-JS-001: eval() with a tainted argument (source: req.query)
let userInput = req.query.q;
eval(userInput);
