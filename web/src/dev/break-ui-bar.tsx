import React from "react";
import { useSearchParams } from "react-router-dom";
import { Check, FlaskConical } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import useBasicState from "@/states/basic";
import useConfigState from "@/states/config";
import useTrafficState from "@/states/traffic";
import {
  createBreakUiDataset,
  type BreakUiMode,
} from "@/dev/worst-case-fixtures";

interface StoreSnapshot {
  basic: ReturnType<typeof useBasicState.getState>;
  config: ReturnType<typeof useConfigState.getState>;
  traffic: ReturnType<typeof useTrafficState.getState>;
}

const fixtureController: {
  snapshot: StoreSnapshot | null;
  wasFixtureActive: boolean;
} = {
  snapshot: null,
  wasFixtureActive: false,
};

function parseMode(raw: string | null): BreakUiMode {
  if (raw === "worst" || raw === "empty" || raw === "one") {
    return raw;
  }
  return "live";
}

function captureLiveSnapshot(): StoreSnapshot {
  return {
    basic: useBasicState.getState(),
    config: useConfigState.getState(),
    traffic: useTrafficState.getState(),
  };
}

function applyModeToStores(mode: BreakUiMode) {
  if (mode === "live") {
    if (!fixtureController.wasFixtureActive) {
      return;
    }
    const snap = fixtureController.snapshot;
    fixtureController.wasFixtureActive = false;
    if (snap) {
      useBasicState.setState({
        fetch: snap.basic.fetch,
        restart: snap.basic.restart,
        data: snap.basic.data,
        initialized: snap.basic.initialized,
      });
      useConfigState.setState({
        fetch: snap.config.fetch,
        fetchFullConfig: snap.config.fetchFullConfig,
        getCertificateInfos: snap.config.getCertificateInfos,
        data: snap.config.data,
        certificateInfos: snap.config.certificateInfos,
        originalToml: snap.config.originalToml,
        fullToml: snap.config.fullToml,
        hcl: snap.config.hcl,
        kdl: snap.config.kdl,
        initialized: snap.config.initialized,
      });
      useTrafficState.setState({
        fetch: snap.traffic.fetch,
        data: snap.traffic.data,
        initialized: snap.traffic.initialized,
      });
      void snap.basic.fetch().catch(() => undefined);
      void snap.config.fetch().catch(() => undefined);
      void snap.config.getCertificateInfos().catch(() => undefined);
      void snap.traffic.fetch().catch(() => undefined);
    }
    return;
  }

  if (!fixtureController.snapshot) {
    fixtureController.snapshot = captureLiveSnapshot();
  }
  const snap = fixtureController.snapshot;
  const dataset = createBreakUiDataset(mode);
  fixtureController.wasFixtureActive = true;

  // Pause background poll overwrites while previewing a stress fixture.
  useBasicState.setState({
    initialized: true,
    data: dataset.basic,
    fetch: async () => dataset.basic,
  });
  useConfigState.setState({
    initialized: true,
    data: dataset.config,
    certificateInfos: dataset.certificateInfos,
    originalToml: dataset.originalToml ?? "",
    fullToml: dataset.fullToml ?? "",
    hcl: dataset.hcl ?? "",
    kdl: dataset.kdl ?? "",
    fetch: async () => dataset.config,
    fetchFullConfig: async () => undefined,
    getCertificateInfos: async () => dataset.certificateInfos,
    version: `fixture-${mode}`,
  });
  useTrafficState.setState({
    initialized: true,
    data: dataset.traffic,
    fetch: async () => dataset.traffic,
  });
  void snap;
}

const MODES: { id: BreakUiMode; label: string }[] = [
  { id: "live", label: "Live" },
  { id: "worst", label: "Worst" },
  { id: "empty", label: "Empty" },
  { id: "one", label: "One" },
];

/** Dev-only header fixture switcher (?data=worst|empty|one). */
export default function BreakUiBar() {
  const [searchParams, setSearchParams] = useSearchParams();
  const mode = parseMode(searchParams.get("data"));

  React.useEffect(() => {
    applyModeToStores(mode);
  }, [mode]);

  const selectMode = (nextMode: BreakUiMode) => {
    const next = new URLSearchParams(searchParams);
    if (nextMode === "live") {
      next.delete("data");
    } else {
      next.set("data", nextMode);
    }
    setSearchParams(next, { replace: true });
  };

  const activeLabel = MODES.find((item) => item.id === mode)?.label ?? "Live";

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        {mode === "live" ? (
          <Button
            type="button"
            variant="ghost"
            size="icon"
            className="size-8 shrink-0 cursor-pointer text-muted-foreground hover:text-foreground"
            title="UI Fixtures (Dev)"
            aria-label="UI Fixtures (Dev)"
          >
            <FlaskConical className="size-4" strokeWidth={1.8} />
          </Button>
        ) : (
          <button
            type="button"
            title={`UI Fixtures: ${activeLabel}`}
            aria-label={`UI Fixtures: ${activeLabel} (Dev)`}
            className="inline-flex size-8 shrink-0 cursor-pointer items-center justify-center gap-1 rounded-md border border-primary/40 bg-primary/10 text-[11.5px] font-medium text-primary hover:bg-primary/15 sm:h-7 sm:w-auto sm:rounded-full sm:px-2"
          >
            <FlaskConical className="size-3.5 shrink-0" />
            <span className="hidden sm:inline">{activeLabel}</span>
          </button>
        )}
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {MODES.map((item) => {
          const active = mode === item.id;
          return (
            <DropdownMenuItem
              key={item.id}
              className="cursor-pointer"
              onClick={() => selectMode(item.id)}
            >
              {active ? (
                <Check className="size-4" />
              ) : (
                <span className="size-4 shrink-0" aria-hidden="true" />
              )}
              <span>{item.label}</span>
            </DropdownMenuItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
