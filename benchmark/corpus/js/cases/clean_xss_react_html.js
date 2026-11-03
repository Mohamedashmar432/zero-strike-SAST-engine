// Sanitized or constant __html values.
const DOMPurify = require('dompurify');
function Bio(props) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(props.bio) }} />;
}
function Spacer() {
  return <div dangerouslySetInnerHTML={{ __html: '<br/>' }} />;
}
module.exports = { Bio, Spacer };
