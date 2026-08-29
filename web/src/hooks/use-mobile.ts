import * as React from "react";

const MOBILE_BREAKPOINT = 768;
const MOBILE_QUERY = `(max-width: ${MOBILE_BREAKPOINT - 1}px)`;

let mediaQuery: MediaQueryList | null = null;

function getMediaQuery() {
  if (!mediaQuery) {
    mediaQuery = window.matchMedia(MOBILE_QUERY);
  }
  return mediaQuery;
}

function subscribe(onStoreChange: () => void) {
  const mql = getMediaQuery();
  mql.addEventListener("change", onStoreChange);
  return () => mql.removeEventListener("change", onStoreChange);
}

/**
 * A media query is an external store, so read it as one. The upstream shadcn
 * version seeds `undefined` and assigns inside an effect, which renders the
 * desktop layout for one frame on a phone — visible as the sidebar rail
 * flashing before the sheet takes over — and now also trips the react-hooks
 * `set-state-in-effect` rule.
 */
export function useIsMobile() {
  return React.useSyncExternalStore(
    subscribe,
    () => getMediaQuery().matches,
    () => false,
  );
}
