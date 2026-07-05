// Negative fixture: none of the ZS-TS rules should fire here.
function add(a: number, b: number): number {
    return a + b;
}

try {
    add(1, 2);
} catch (e) {
    console.error(e);
}
