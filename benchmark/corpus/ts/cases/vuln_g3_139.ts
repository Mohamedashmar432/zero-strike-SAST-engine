// ZS-TS-139: CWE-601: NextResponse.redirect to a header-supplied URL
const { NextResponse } = require('next/server');
function GET(request) {
  const returnUrl = request.headers.get('x-return-url');
  return NextResponse.redirect(new URL(returnUrl, request.url));
}
