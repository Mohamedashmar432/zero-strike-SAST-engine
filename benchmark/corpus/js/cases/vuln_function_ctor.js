// ZS-JS-004: new Function() with a tainted argument (source: req.query)
let userInput = req.query.expr;
new Function(userInput);
