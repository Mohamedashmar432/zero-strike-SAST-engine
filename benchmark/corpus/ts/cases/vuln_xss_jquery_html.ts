declare const $: any;

export function showQuery(): void {
  const q: string | null = new URLSearchParams(location.search).get('q');
  $('#out').html(q);
}
