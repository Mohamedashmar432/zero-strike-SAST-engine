function compose() {
  const compile = new Function('name', 'return name;');
  return compile('x');
}
