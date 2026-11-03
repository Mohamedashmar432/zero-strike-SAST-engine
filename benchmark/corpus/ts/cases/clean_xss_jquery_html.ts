declare const $: any;

export function showLoading(): string {
  $('#out').html('<i>loading</i>');
  const v: string = $('#out').html();
  return v;
}
