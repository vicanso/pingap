import React from "react";
import { toast } from "sonner";
import { useShallow } from "zustand/react/shallow";
import {
  Activity,
  CheckCircle2,
  LoaderCircle,
  Play,
  RefreshCw,
  XCircle,
} from "lucide-react";
import { PageShell } from "@/components/page-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import request from "@/helpers/request";
import { formatError } from "@/helpers/util";
import { useI18n } from "@/i18n";
import useConfigState from "@/states/config";

interface MatchedRouteDetail {
  name: string;
  weight: number;
  upstream: string;
  fallback_upstream: string;
  plugins: string[];
  rewritten_uri?: string | null;
}

interface RouteCandidateResult {
  name: string;
  weight: number;
  matched: boolean;
  host_path_matched: boolean;
  conditions_matched: boolean;
  reason: string;
  upstream: string;
  plugins: string[];
}

interface RouteMatchResponse {
  server: string;
  normalized_path: string;
  matched: MatchedRouteDetail | null;
  candidates: RouteCandidateResult[];
}

type EventKindFilter = "all" | "5xx" | "dry_run" | "reload_fail";

interface RecentEventItem {
  id: number;
  ts: number;
  kind: "5xx" | "dry_run" | "reload_fail";
  server?: string;
  location?: string;
  status?: number;
  method?: string;
  host?: string;
  uri?: string;
  client_ip?: string;
  category?: string;
  message: string;
}

const HTTP_METHODS = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "HEAD",
  "OPTIONS",
];

function parseHeaderLines(raw: string): Record<string, string> {
  const headers: Record<string, string> = {};
  raw.split("\n").forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) {
      return;
    }
    const idx = trimmed.indexOf(":");
    if (idx <= 0) {
      return;
    }
    const key = trimmed.slice(0, idx).trim();
    const val = trimmed.slice(idx + 1).trim();
    if (key) {
      headers[key] = val;
    }
  });
  return headers;
}

function formatEventTime(ts: number): string {
  if (!ts) {
    return "—";
  }
  return new Date(ts * 1000).toLocaleString();
}

function eventBadgeVariant(
  kind: RecentEventItem["kind"],
): "destructive" | "secondary" | "outline" {
  switch (kind) {
    case "5xx":
      return "destructive";
    case "reload_fail":
      return "secondary";
    default:
      return "outline";
  }
}

export default function Diagnostics() {
  const diagI18n = useI18n("diagnostics");
  const [config] = useConfigState(useShallow((state) => [state.data]));
  const serverNames = React.useMemo(
    () => Object.keys(config.servers || {}).sort(),
    [config.servers],
  );

  // Route Match Simulator state
  const [server, setServer] = React.useState("");
  const selectedServer = server || serverNames[0] || "";
  const [method, setMethod] = React.useState("GET");
  const [host, setHost] = React.useState("");
  const [path, setPath] = React.useState("/");
  const [query, setQuery] = React.useState("");
  const [cookie, setCookie] = React.useState("");
  const [headersText, setHeadersText] = React.useState("");
  const [simulating, setSimulating] = React.useState(false);
  const [simResult, setSimResult] = React.useState<RouteMatchResponse | null>(
    null,
  );

  const handleSimulate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (simulating) {
      return;
    }
    setSimulating(true);
    try {
      const headers = parseHeaderLines(headersText);
      const res = await request.post<RouteMatchResponse>("/debug/route-match", {
        server: selectedServer || undefined,
        method,
        host: host.trim() || undefined,
        path: path.trim() || "/",
        query: query.trim() || undefined,
        cookie: cookie.trim() || undefined,
        headers: Object.keys(headers).length > 0 ? headers : undefined,
      });
      setSimResult(res.data);
    } catch (err) {
      toast(diagI18n("simulateFail"), {
        description: formatError(err),
      });
    } finally {
      setSimulating(false);
    }
  };

  // Recent Events state
  const [kindFilter, setKindFilter] = React.useState<EventKindFilter>("all");
  const [autoRefresh, setAutoRefresh] = React.useState(false);
  const [loadingEvents, setLoadingEvents] = React.useState(false);
  const [events, setEvents] = React.useState<RecentEventItem[]>([]);

  const fetchEvents = React.useCallback(async () => {
    setLoadingEvents(true);
    try {
      const res = await request.get<{ events: RecentEventItem[] }>(
        "/debug/events",
        {
          params: {
            kind: kindFilter === "all" ? "" : kindFilter,
            limit: 200,
          },
        },
      );
      setEvents(res.data.events || []);
    } catch (err) {
      toast(diagI18n("eventsFetchFail"), {
        description: formatError(err),
      });
    } finally {
      setLoadingEvents(false);
    }
  }, [kindFilter, diagI18n]);

  React.useEffect(() => {
    let active = true;
    request
      .get<{ events: RecentEventItem[] }>("/debug/events", {
        params: {
          kind: kindFilter === "all" ? "" : kindFilter,
          limit: 200,
        },
      })
      .then((res) => {
        if (active) {
          setEvents(res.data.events || []);
        }
      })
      .catch((err) => {
        if (active) {
          toast(diagI18n("eventsFetchFail"), {
            description: formatError(err),
          });
        }
      });
    return () => {
      active = false;
    };
  }, [kindFilter, diagI18n]);

  React.useEffect(() => {
    if (!autoRefresh) {
      return;
    }
    const id = window.setInterval(() => {
      fetchEvents();
    }, 5000);
    return () => window.clearInterval(id);
  }, [autoRefresh, fetchEvents]);

  return (
    <PageShell title={diagI18n("title")} description={diagI18n("description")}>
      <Tabs defaultValue="route-match" className="space-y-4">
        <TabsList className="grid h-auto w-full max-w-md grid-cols-1 gap-1 group-data-[orientation=horizontal]/tabs:h-auto sm:grid-cols-2 sm:group-data-[orientation=horizontal]/tabs:h-9">
          <TabsTrigger value="route-match" className="cursor-pointer">
            {diagI18n("tabRouteMatch")}
          </TabsTrigger>
          <TabsTrigger value="events" className="cursor-pointer">
            {diagI18n("tabRecentEvents")}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="route-match" className="space-y-4">
          <Card className="border-border">
            <CardHeader className="pb-3">
              <CardTitle className="text-base">
                {diagI18n("simulatorTitle")}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSimulate} className="space-y-4">
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
                  <div className="space-y-1.5">
                    <Label>{diagI18n("serverLabel")}</Label>
                    <Select
                      value={selectedServer}
                      onValueChange={setServer}
                      disabled={serverNames.length === 0}
                    >
                      <SelectTrigger className="w-full cursor-pointer">
                        <SelectValue
                          placeholder={diagI18n("serverPlaceholder")}
                        />
                      </SelectTrigger>
                      <SelectContent>
                        {serverNames.map((name) => (
                          <SelectItem key={name} value={name}>
                            {name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label>{diagI18n("methodLabel")}</Label>
                    <Select value={method} onValueChange={setMethod}>
                      <SelectTrigger className="w-full cursor-pointer">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {HTTP_METHODS.map((m) => (
                          <SelectItem key={m} value={m}>
                            {m}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-1.5">
                    <Label>{diagI18n("hostLabel")}</Label>
                    <Input
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      value={host}
                      onChange={(e) => setHost(e.target.value)}
                      placeholder="api.example.com"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{diagI18n("pathLabel")}</Label>
                    <Input
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      value={path}
                      onChange={(e) => setPath(e.target.value)}
                      placeholder="/v1/chat/completions"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label>{diagI18n("queryLabel")}</Label>
                    <Input
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      placeholder="version=2&debug=1"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label>{diagI18n("cookieLabel")}</Label>
                    <Input
                      autoCapitalize="none"
                      autoCorrect="off"
                      spellCheck={false}
                      value={cookie}
                      onChange={(e) => setCookie(e.target.value)}
                      placeholder="canary=1; session=abc"
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label>{diagI18n("headersLabel")}</Label>
                  <Textarea
                    rows={3}
                    autoCapitalize="none"
                    autoCorrect="off"
                    spellCheck={false}
                    className="font-mono text-base sm:text-xs"
                    value={headersText}
                    onChange={(e) => setHeadersText(e.target.value)}
                    placeholder={"x-canary: yes\nauthorization: Bearer token"}
                  />
                </div>

                <Button
                  type="submit"
                  className="cursor-pointer gap-2"
                  disabled={simulating || serverNames.length === 0}
                >
                  {simulating ? (
                    <LoaderCircle className="h-4 w-4 animate-spin" />
                  ) : (
                    <Play className="h-4 w-4" />
                  )}
                  {diagI18n("runSimulation")}
                </Button>
              </form>
            </CardContent>
          </Card>

          {simResult && (
            <div className="space-y-4">
              <Card className="border-border">
                <CardHeader className="pb-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <CardTitle className="flex items-center gap-2 text-base">
                      {simResult.matched ? (
                        <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                      ) : (
                        <XCircle className="h-4 w-4 text-muted-foreground" />
                      )}
                      {simResult.matched
                        ? diagI18n("matchedLocation", {
                            name: simResult.matched.name,
                          })
                        : diagI18n("noRouteMatched")}
                    </CardTitle>
                    <Badge
                      variant="outline"
                      title={simResult.normalized_path}
                      className="max-w-full truncate font-mono text-xs"
                    >
                      {diagI18n("normalizedPath")}: {simResult.normalized_path}
                    </Badge>
                  </div>
                </CardHeader>
                {simResult.matched && (
                  <CardContent className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
                    <div>
                      <div className="text-xs text-muted-foreground">
                        {diagI18n("upstreamLabel")}
                      </div>
                      <div className="font-mono font-medium break-all">
                        {simResult.matched.upstream || "—"}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground">
                        {diagI18n("fallbackUpstreamLabel")}
                      </div>
                      <div className="font-mono font-medium break-all">
                        {simResult.matched.fallback_upstream || "—"}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground">
                        {diagI18n("weightLabel")}
                      </div>
                      <div className="font-mono font-medium">
                        {simResult.matched.weight}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground">
                        {diagI18n("rewrittenUriLabel")}
                      </div>
                      <div className="font-mono font-medium break-all">
                        {simResult.matched.rewritten_uri || "—"}
                      </div>
                    </div>
                    <div className="sm:col-span-2 lg:col-span-4">
                      <div className="mb-1 text-xs text-muted-foreground">
                        {diagI18n("pluginsChainLabel")}
                      </div>
                      {simResult.matched.plugins.length > 0 ? (
                        <div className="flex flex-wrap gap-1.5">
                          {simResult.matched.plugins.map((p, idx) => (
                            <Badge key={`${p}-${idx}`} variant="secondary">
                              {idx + 1}. {p}
                            </Badge>
                          ))}
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </div>
                  </CardContent>
                )}
              </Card>

              <Card className="border-border">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">
                    {diagI18n("candidatesTitle")}
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{diagI18n("colLocation")}</TableHead>
                        <TableHead className="figure text-right">
                          {diagI18n("colWeight")}
                        </TableHead>
                        <TableHead>{diagI18n("colUpstream")}</TableHead>
                        <TableHead>{diagI18n("colHostPath")}</TableHead>
                        <TableHead>{diagI18n("colConditions")}</TableHead>
                        <TableHead>{diagI18n("colReason")}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {simResult.candidates.length === 0 ? (
                        <TableRow>
                          <TableCell
                            colSpan={6}
                            className="py-6 text-center text-sm text-muted-foreground"
                          >
                            {diagI18n("noCandidates")}
                          </TableCell>
                        </TableRow>
                      ) : (
                        simResult.candidates.map((item) => (
                          <TableRow key={item.name}>
                            <TableCell
                              className="max-w-[220px] truncate font-mono font-medium"
                              title={item.name}
                            >
                              {item.name}
                            </TableCell>
                            <TableCell className="figure text-right font-mono">
                              {item.weight}
                            </TableCell>
                            <TableCell
                              className="max-w-[220px] truncate font-mono text-xs"
                              title={item.upstream || undefined}
                            >
                              {item.upstream || "—"}
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={
                                  item.host_path_matched
                                    ? "secondary"
                                    : "outline"
                                }
                              >
                                {item.host_path_matched ? "✓" : "✕"}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={
                                  item.conditions_matched
                                    ? "secondary"
                                    : "outline"
                                }
                              >
                                {item.conditions_matched ? "✓" : "✕"}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              <Badge
                                variant={item.matched ? "default" : "outline"}
                              >
                                {item.reason}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        <TabsContent value="events" className="space-y-4">
          <Card className="border-border">
            <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-3 pb-3">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-base">
                  {diagI18n("eventsTitle")}
                </CardTitle>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <div className="flex flex-wrap items-center gap-1 rounded-md border border-border p-0.5">
                  {(["all", "5xx", "dry_run", "reload_fail"] as const).map(
                    (kind) => (
                      <Button
                        key={kind}
                        type="button"
                        size="sm"
                        variant={kindFilter === kind ? "default" : "ghost"}
                        className="h-7 cursor-pointer px-2.5 text-xs"
                        onClick={() => setKindFilter(kind)}
                      >
                        {kind === "all" ? diagI18n("filterAll") : kind}
                      </Button>
                    ),
                  )}
                </div>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <Switch
                    checked={autoRefresh}
                    onCheckedChange={setAutoRefresh}
                    id="events-auto-refresh"
                  />
                  <Label
                    htmlFor="events-auto-refresh"
                    className="cursor-pointer text-xs"
                  >
                    {diagI18n("autoRefresh")}
                  </Label>
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  className="h-8 cursor-pointer gap-1.5 text-xs"
                  disabled={loadingEvents}
                  onClick={fetchEvents}
                >
                  <RefreshCw
                    className={`h-3.5 w-3.5 ${loadingEvents ? "animate-spin" : ""}`}
                  />
                  {diagI18n("refresh")}
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {events.length === 0 ? (
                <div className="py-8 text-center text-sm text-muted-foreground">
                  {diagI18n("noEvents")}
                </div>
              ) : (
                <>
                  <div className="divide-y divide-border md:hidden">
                    {events.map((ev) => {
                      const target = [ev.server, ev.location, ev.category]
                        .filter(Boolean)
                        .join(" / ");
                      const requestText = [ev.method, ev.host, ev.uri]
                        .filter(Boolean)
                        .join(" ");
                      return (
                        <div
                          key={ev.id}
                          className="space-y-1.5 px-4 py-3 text-xs"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <Badge variant={eventBadgeVariant(ev.kind)}>
                                {ev.kind}
                              </Badge>
                              {ev.status != null && (
                                <span className="figure font-mono font-medium">
                                  {ev.status}
                                </span>
                              )}
                            </div>
                            <span className="figure font-mono text-[11px] text-muted-foreground">
                              {formatEventTime(ev.ts)}
                            </span>
                          </div>
                          {target && (
                            <div className="font-mono break-all text-secondary-foreground">
                              {target}
                            </div>
                          )}
                          {(requestText || ev.client_ip) && (
                            <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 font-mono text-[11px] text-muted-foreground">
                              {requestText && (
                                <span className="min-w-0 break-all">
                                  {requestText}
                                </span>
                              )}
                              {ev.client_ip && (
                                <span className="shrink-0">{ev.client_ip}</span>
                              )}
                            </div>
                          )}
                          <p className="break-words text-foreground">
                            {ev.message || "—"}
                          </p>
                        </div>
                      );
                    })}
                  </div>
                  <div className="hidden overflow-x-auto md:block">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>{diagI18n("colTime")}</TableHead>
                          <TableHead>{diagI18n("colKind")}</TableHead>
                          <TableHead className="figure text-right">
                            {diagI18n("colStatus")}
                          </TableHead>
                          <TableHead>{diagI18n("colTarget")}</TableHead>
                          <TableHead>{diagI18n("colRequest")}</TableHead>
                          <TableHead>{diagI18n("colClientIp")}</TableHead>
                          <TableHead>{diagI18n("colMessage")}</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {events.map((ev) => {
                          const target = [ev.server, ev.location, ev.category]
                            .filter(Boolean)
                            .join(" / ");
                          const requestText = [ev.method, ev.host, ev.uri]
                            .filter(Boolean)
                            .join(" ");
                          return (
                            <TableRow key={ev.id}>
                              <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                                {formatEventTime(ev.ts)}
                              </TableCell>
                              <TableCell>
                                <Badge variant={eventBadgeVariant(ev.kind)}>
                                  {ev.kind}
                                </Badge>
                              </TableCell>
                              <TableCell className="figure text-right font-mono text-xs">
                                {ev.status ?? "—"}
                              </TableCell>
                              <TableCell
                                className="max-w-[220px] truncate font-mono text-xs"
                                title={target || undefined}
                              >
                                {target || "—"}
                              </TableCell>
                              <TableCell
                                className="max-w-[200px] truncate font-mono text-xs"
                                title={requestText || undefined}
                              >
                                {requestText || "—"}
                              </TableCell>
                              <TableCell
                                className="max-w-[140px] truncate font-mono text-xs"
                                title={ev.client_ip || undefined}
                              >
                                {ev.client_ip || "—"}
                              </TableCell>
                              <TableCell className="min-w-[240px] max-w-[460px] whitespace-normal break-words text-xs">
                                {ev.message || "—"}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </PageShell>
  );
}
