declare const React: any;
declare const DOMPurify: any;

export function Bio(props: { bio: string }) {
  return React.createElement('div', { dangerouslySetInnerHTML: { __html: DOMPurify.sanitize(props.bio) } });
}

export function Br() {
  return React.createElement('div', { dangerouslySetInnerHTML: { __html: '<br/>' } });
}
