// Phases 3 and 4: parameter-only taint, and argument 0 being a function.
//
// Both call sites pass a function, which is the practice the setTimeout rule's
// own message recommends -- it fired on them anyway, so the rule flagged its
// own remediation. `delay` and `value` are function parameters, tainted only
// by seeding, never traced to a source.
export function useDebounced<T>(value: T, delay: number): T {
  let settled = value;
  const timer = setTimeout(() => {
    settled = value;
  }, delay);
  clearTimeout(timer);
  return settled;
}

export function waitForFrame(video: HTMLVideoElement, done: () => void) {
  setTimeout(() => {
    video.removeEventListener("loadeddata", done);
  }, 2000);
}
