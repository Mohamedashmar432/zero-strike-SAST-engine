// ZS-TS-010: new Function() with a tainted argument (source: req.query)
let userInput: string = req.query.expr;
new Function(userInput);
