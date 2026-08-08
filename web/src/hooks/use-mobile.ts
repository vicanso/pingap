import * as React from "react";

const MOBILE_BREAKPOINT = 768;

function subscribe(onStoreChange: () => void) {
  const mql = window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`);
  mql.addEventListener("change", onStoreChange);
  return () => mql.removeEventListener("change", onStoreChange);
}

const getSnapshot = () => window.innerWidth < MOBILE_BREAKPOINT;

/**
 * Read the viewport as an external store rather than mirroring it into state
 * from an effect: the width is known during the first render, so there is no
 * desktop-then-mobile flash and no setState-in-effect cascade.
 */
export function useIsMobile() {
  return React.useSyncExternalStore(subscribe, getSnapshot);
}
