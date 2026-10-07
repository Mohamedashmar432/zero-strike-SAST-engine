// ZS-TS-151: CWE-601: server action redirecting to a form-supplied URL
const { redirect } = require('next/navigation');
async function finish(formData) {
  const next = formData.get('next');
  redirect(next);
}
