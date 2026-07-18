// ZS-TS-038: prototype pollution — __proto__ assigned from request input
function applySettings(req: any, res: any) {
  const payload: any = req.body.data;
  const settings: any = {};
  settings.__proto__ = payload;
}
