// ZS-TS-172: template compiled with new Function
function compose() {
  const letterBody = loadTemplate();
  const compile = new Function('name', `return \`${letterBody}\`;`);
  return compile('x');
}
