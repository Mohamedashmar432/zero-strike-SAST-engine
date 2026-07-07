// ZS-JS-005: outerHTML assignment with a tainted RHS (source: req.query)
let userInput = req.query.name;
el.outerHTML = userInput;
