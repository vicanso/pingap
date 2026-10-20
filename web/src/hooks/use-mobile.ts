import * as React from "react";

const MOBILE_BREAKPOINT = 768;
/** Below this the navigation folds into the top bar: a tablet's width is
 * the page's, not the page's and a 256px sidebar's. */
const COMPACT_BREAKPOINT = 1024;

/** A media query as an external store, its list made when first asked. */
function mediaStore(query: string) {
  let list: MediaQueryList | null = null;
  const get = () => {
    if (!list) {
      list = window.matchMedia(query);
    }
    return list;
  };
  return {
    subscribe(onStoreChange: () => void) {
      const mql = get();
      mql.addEventListener("change", onStoreChange);
      return () => mql.removeEventListener("change", onStoreChange);
    },
    matches: () => get().matches,
  };
}

const mobile = mediaStore(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`);
const compact = mediaStore(`(max-width: ${COMPACT_BREAKPOINT - 1}px)`);

/**
 * A media query is an external store, so read it as one. The upstream shadcn
 * version seeds `undefined` and assigns inside an effect, which renders the
 * desktop layout for one frame on a phone — visible as the sidebar rail
 * flashing before the sheet takes over — and now also trips the react-hooks
 * `set-state-in-effect` rule.
 */
export function useIsMobile() {
  return React.useSyncExternalStore(
    mobile.subscribe,
    mobile.matches,
    () => false,
  );
}

/** A phone or a tablet: the width where the sidebar is a sheet behind the
 * menu button and the page is the whole screen. */
export function useIsCompact() {
  return React.useSyncExternalStore(
    compact.subscribe,
    compact.matches,
    () => false,
  );
}
