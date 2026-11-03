// dangerouslySetInnerHTML fed a raw prop.
function Bio(props) {
  return <div dangerouslySetInnerHTML={{ __html: props.bio }} />;
}
module.exports = Bio;
