// ZS-TS-002: innerHTML assignment with a tainted RHS (source: req.query)
let userInput: string = req.query.name;
el.innerHTML = userInput;
