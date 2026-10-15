import { useCallback, useSyncExternalStore, type SetStateAction } from 'react';

/**
 * State that outlives the component, for pages that should come back as they were left.
 * Values live in memory for the browser tab (not across a reload). A setter keeps working while
 * the page is closed, so a test that is still running keeps recording its progress and result.
 */
const values = new Map<string, unknown>();
const listeners = new Map<string, Set<() => void>>();

function notify(key: string) {
  listeners.get(key)?.forEach(fn => fn());
}

export function setSticky<T>(key: string, next: SetStateAction<T>) {
  const prev = values.get(key) as T;
  const value = typeof next === 'function' ? (next as (p: T) => T)(prev) : next;
  if (Object.is(value, prev)) return;
  values.set(key, value);
  notify(key);
}

/** Removes every value whose key starts with `prefix`, so the next mount starts fresh. */
export function clearSticky(prefix: string) {
  for (const key of Array.from(values.keys())) {
    if (key.startsWith(prefix)) {
      values.delete(key);
      notify(key);
    }
  }
}

export function useStickyState<T>(key: string, initial: T | (() => T)): [T, (next: SetStateAction<T>) => void] {
  if (!values.has(key)) values.set(key, typeof initial === 'function' ? (initial as () => T)() : initial);

  const subscribe = useCallback((fn: () => void) => {
    let set = listeners.get(key);
    if (!set) listeners.set(key, (set = new Set()));
    set.add(fn);
    return () => { set!.delete(fn); };
  }, [key]);

  const value = useSyncExternalStore(subscribe, () => {
    // A key cleared while mounted falls back to its initial value
    if (!values.has(key)) values.set(key, typeof initial === 'function' ? (initial as () => T)() : initial);
    return values.get(key) as T;
  });

  const set = useCallback((next: SetStateAction<T>) => setSticky<T>(key, next), [key]);
  return [value, set];
}
