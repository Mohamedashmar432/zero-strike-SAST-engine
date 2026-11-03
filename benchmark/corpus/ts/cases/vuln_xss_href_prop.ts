export function follow(anchor: HTMLAnchorElement, form: HTMLFormElement): void {
  const u: string | null = new URLSearchParams(location.search).get('next');
  anchor.href = u as string;
  form.action = u as string;
}
