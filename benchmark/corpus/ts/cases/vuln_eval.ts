// ZS-TS-001: eval() with a tainted argument (source: req.query)
let userInput: string = req.query.q;
eval(userInput);
