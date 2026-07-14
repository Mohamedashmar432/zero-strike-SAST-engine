// ZS-TS-011: outerHTML assignment with a tainted RHS (source: req.query)
let userInput: string = req.query.name;
el.outerHTML = userInput;
