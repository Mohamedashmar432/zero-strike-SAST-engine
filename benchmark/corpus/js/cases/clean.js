// Negative fixture: none of the ZS-JS rules should fire here.
function add(a, b) {
    return a + b;
}

try {
    add(1, 2);
} catch (e) {
    console.error(e);
}
