import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { Inbox } from "lucide-react";

import { EmptyState } from "@/components/data-display/EmptyState";
import { ErrorState } from "@/components/data-display/ErrorState";
import { LoadingState } from "@/components/data-display/LoadingState";
import { SplitView } from "@/components/layout/SplitView";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { AlertDetailPanel } from "@/features/alerts/components/AlertDetailPanel";
import {
  statusPresetFilters,
  useAlerts,
} from "@/features/alerts/hooks/useAlerts";
import { useNetworks } from "@/features/dashboard/hooks/useDashboardData";
import { useDebounce } from "@/hooks/useDebounce";
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts";
import type { KeyboardShortcut } from "@/hooks/useKeyboardShortcuts";
import type { Alert, AlertStatusPreset, Severity } from "@/lib/types";
import { ALERT_STATUS } from "@/lib/terminology";
import { cn, formatRelativeTime } from "@/lib/utils";

const PAGE_SIZE = 50;

const SEVERITY_DOT: Record<Severity, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  info: "bg-blue-500",
};

interface AlertsInboxProps {
  selectedAlertId?: number;
  initialSource?: string;
  initialSearch?: string;
}

export function AlertsInbox({
  selectedAlertId,
  initialSource,
  initialSearch,
}: AlertsInboxProps) {
  const navigate = useNavigate();

  const [status, setStatus] = useState<AlertStatusPreset | "all">("open");
  const [source, setSource] = useState(initialSource ?? "");
  const [networkId, setNetworkId] = useState<number | "">("");
  const [searchInput, setSearchInput] = useState(initialSearch ?? "");
  const [page, setPage] = useState(0);
  const search = useDebounce(searchInput, 300);

  const [allowOpen, setAllowOpen] = useState(false);
  const [muteOpen, setMuteOpen] = useState(false);
  const [assignOpen, setAssignOpen] = useState(false);

  const networks = useNetworks();

  const alertsQuery = useAlerts({
    ...(status === "all" ? {} : statusPresetFilters(status)),
    source: source || undefined,
    network_id: networkId === "" ? undefined : networkId,
    search: search || undefined,
    offset: page * PAGE_SIZE,
    limit: PAGE_SIZE,
  });

  const alerts = useMemo(
    () => alertsQuery.data?.alerts ?? [],
    [alertsQuery.data],
  );
  const total = alertsQuery.data?.total ?? 0;
  const severityCounts = alertsQuery.data?.severity_counts ?? {};

  const selectedId = selectedAlertId ?? alerts[0]?.id;
  const selectedIndex = alerts.findIndex((a) => a.id === selectedId);
  const selectedAlert: Alert | undefined =
    selectedIndex >= 0 ? alerts[selectedIndex] : undefined;

  const selectAlert = (alert: Alert | undefined) => {
    if (!alert) return;
    void navigate({
      to: "/alerts/$alertId",
      params: { alertId: String(alert.id) },
      replace: true,
    });
  };

  const shortcuts: KeyboardShortcut[] = useMemo(
    () => [
      {
        key: "j",
        description: "Next alert",
        handler: () => {
          const next = selectedIndex < 0 ? 0 : selectedIndex + 1;
          selectAlert(alerts[Math.min(next, alerts.length - 1)]);
        },
      },
      {
        key: "k",
        description: "Previous alert",
        handler: () => {
          const prev = selectedIndex < 0 ? 0 : selectedIndex - 1;
          selectAlert(alerts[Math.max(prev, 0)]);
        },
      },
      {
        key: "a",
        description: "Allow (opens dialog)",
        handler: () => {
          if (selectedAlert && !selectedAlert.dismissed) setAllowOpen(true);
        },
      },
      {
        key: "m",
        description: "Mute (opens dialog)",
        handler: () => {
          if (selectedAlert && !selectedAlert.dismissed) setMuteOpen(true);
        },
      },
      {
        key: "s",
        description: "Assign (opens control)",
        handler: () => {
          if (selectedAlert) setAssignOpen(true);
        },
      },
      {
        key: "Enter",
        description: "Open host",
        handler: () => {
          if (selectedAlert?.host_id) {
            void navigate({
              to: "/hosts/$hostId",
              params: { hostId: String(selectedAlert.host_id) },
            });
          }
        },
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [alerts, selectedIndex, selectedAlert],
  );
  useKeyboardShortcuts(shortcuts);

  const list = (
    <div className="flex h-full flex-col">
      {/* Filters */}
      <div className="space-y-2 border-b border-border p-3">
        <div className="flex gap-1 rounded-md bg-secondary/50 p-0.5">
          {(["open", "muted", "allowed", "all"] as const).map((value) => (
            <button
              key={value}
              type="button"
              onClick={() => {
                setStatus(value);
                setPage(0);
              }}
              title={
                value === "all" ? undefined : ALERT_STATUS[value].description
              }
              className={cn(
                "flex-1 rounded px-2 py-1 text-xs transition-colors",
                status === value
                  ? "bg-accent text-accent-foreground font-emphasis"
                  : "text-muted-foreground hover:text-foreground",
              )}
            >
              {value === "all" ? "All" : ALERT_STATUS[value].label}
            </button>
          ))}
        </div>
        <Input
          value={searchInput}
          onChange={(e) => {
            setSearchInput(e.target.value);
            setPage(0);
          }}
          placeholder="Search IP, hostname, text..."
          className="h-8 text-sm"
        />
        <div className="flex gap-2">
          <Select
            value={source}
            onChange={(e) => {
              setSource(e.target.value);
              setPage(0);
            }}
            className="h-8 flex-1 text-xs"
          >
            <option value="">All sources</option>
            <option value="port">Port</option>
            <option value="ssh">SSH</option>
            <option value="nse">NSE</option>
            <option value="gvm">GVM</option>
            <option value="nuclei">Nuclei</option>
          </Select>
          <Select
            value={networkId}
            onChange={(e) => {
              setNetworkId(e.target.value ? Number(e.target.value) : "");
              setPage(0);
            }}
            className="h-8 flex-1 text-xs"
          >
            <option value="">All networks</option>
            {(networks.data?.networks ?? []).map((n) => (
              <option key={n.id} value={n.id}>
                {n.name}
              </option>
            ))}
          </Select>
        </div>
        <div className="flex items-center gap-3 px-1 text-xs text-muted-foreground">
          <span>{total} alerts</span>
          {(["critical", "high", "medium", "info"] as const).map(
            (sev) =>
              (severityCounts[sev] ?? 0) > 0 && (
                <span key={sev} className="flex items-center gap-1">
                  <span
                    className={cn("h-2 w-2 rounded-full", SEVERITY_DOT[sev])}
                  />
                  {severityCounts[sev]}
                </span>
              ),
          )}
        </div>
      </div>

      {/* Rows */}
      <div className="flex-1 overflow-y-auto">
        {alertsQuery.isLoading && <LoadingState rows={8} />}
        {alertsQuery.error && (
          <ErrorState
            message={alertsQuery.error.message}
            onRetry={alertsQuery.refetch}
          />
        )}
        {!alertsQuery.isLoading && !alertsQuery.error && alerts.length === 0 && (
          <EmptyState
            icon={Inbox}
            title={status === "open" ? "Inbox zero" : "No alerts"}
            message={
              status === "open"
                ? "No open alerts need a decision."
                : "No alerts match the current filters."
            }
          />
        )}
        {alerts.map((alert) => (
          <button
            key={alert.id}
            type="button"
            onClick={() => selectAlert(alert)}
            className={cn(
              "block w-full border-b border-border px-3 py-2.5 text-left transition-colors",
              alert.id === selectedId
                ? "bg-accent"
                : "hover:bg-accent/50",
            )}
          >
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  "h-2 w-2 shrink-0 rounded-full",
                  SEVERITY_DOT[alert.severity],
                )}
              />
              <span className="truncate text-sm text-foreground">
                {alert.message}
              </span>
            </div>
            <div className="mt-1 flex items-center gap-2 pl-4 text-xs text-muted-foreground">
              <span className="font-mono">
                {alert.ip}
                {alert.port ? `:${alert.port}` : ""}
              </span>
              {alert.network_name && (
                <span className="truncate">{alert.network_name}</span>
              )}
              <span className="ml-auto shrink-0">
                {formatRelativeTime(alert.created_at)}
              </span>
            </div>
          </button>
        ))}
      </div>

      {/* Pagination */}
      {total > PAGE_SIZE && (
        <div className="flex items-center justify-between border-t border-border p-2 text-xs text-muted-foreground">
          <Button
            variant="ghost"
            size="sm"
            disabled={page === 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
          >
            Prev
          </Button>
          <span>
            {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, total)} of{" "}
            {total}
          </span>
          <Button
            variant="ghost"
            size="sm"
            disabled={(page + 1) * PAGE_SIZE >= total}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </Button>
        </div>
      )}
    </div>
  );

  const detail = selectedId ? (
    <div className="p-6">
      <AlertDetailPanel
        key={selectedId}
        alertId={selectedId}
        allowOpen={allowOpen}
        onAllowOpenChange={setAllowOpen}
        muteOpen={muteOpen}
        onMuteOpenChange={setMuteOpen}
        assignOpen={assignOpen}
        onAssignOpenChange={setAssignOpen}
      />
    </div>
  ) : (
    <EmptyState
      icon={Inbox}
      title="No alert selected"
      message="Select an alert from the list. Shortcuts: j/k navigate, A allow, M mute, S assign."
    />
  );

  return (
    <div className="-m-6 h-[calc(100vh-3.5rem)]">
      <SplitView list={list} detail={detail} />
    </div>
  );
}
