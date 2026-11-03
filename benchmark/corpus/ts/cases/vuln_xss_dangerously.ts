declare const React: any;

export function Bio(props: { bio: string }) {
  return React.createElement('div', { dangerouslySetInnerHTML: { __html: props.bio } });
}
