// ZS-JS-002: innerHTML assignment with a tainted RHS (source: req.query)
let userInput = req.query.name;
el.innerHTML = userInput;
