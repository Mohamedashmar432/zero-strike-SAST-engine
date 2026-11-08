const m = /ab+c/.exec(Buffer.from(input, 'base64').toString());
console.log(m);
