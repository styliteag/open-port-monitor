import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { Download, Inbox } from "lucide-react";
import { toast } from "sonner";

import { EmptyState } from "@/components/data-display/EmptyState";
import { ErrorState } from "@/components/data-display/ErrorState";
import { LoadingState } from "@/components/data-display/LoadingState";
import { SplitView } from "@/components/layout/SplitView";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { AcceptModal } from "@/features/alerts/components/AcceptModal";
import { AlertDetailPanel } from "@/features/alerts/components/AlertDetailPanel";
import { DeleteConfirmModal } from "@/features/alerts/components/DeleteConfirmModal";
import { DismissModal } from "@/features/alerts/components/DismissModal";
import {
  statusPresetFilters,
  useAlerts,
  useAlertMutations,
} from "@/features/alerts/hooks/useAlerts";
import { useNetworks } from "@/features/dashboard/hooks/useDashboardData";
import { useDebounce } from "@/hooks/useDebounce";
import { useKeyboardShortcuts } from "@/hooks/useKeyboardShortcuts";
import type { KeyboardShortcut } from "@/hooks/useKeyboardShortcuts";
import type { Alert, AlertStatusPreset, Severity } from "@/lib/types";
import { ALERT_STATUS } from "@/lib/terminology";
import { useAuthStore } from "@/stores/auth.store";
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

  // Bulk selection (parity: bulk actions + permanent deletion)
  const [selectedIds, setSelectedIds] = useState<ReadonlySet<number>>(
    new Set(),
  );
  const [bulkAllowOpen, setBulkAllowOpen] = useState(false);
  const [bulkMuteOpen, setBulkMuteOpen] = useState(false);
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const { bulkDelete } = useAlertMutations();

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

  const toggleSelected = (id: number) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const clearSelection = () => setSelectedIds(new Set());

  const selectedSeverityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const alert of alerts) {
      if (selectedIds.has(alert.id)) {
        counts[alert.severity] = (counts[alert.severity] ?? 0) + 1;
      }
    }
    return counts;
  }, [alerts, selectedIds]);

  // The export endpoint predates the queue/policy dimensions — map the
  // status preset onto its dismissed param (Allowed exports need no
  // narrower server filter than "dismissed").
  const exportAlerts = async (format: "csv" | "pdf") => {
    const params = new URLSearchParams();
    if (status === "open") params.set("dismissed", "false");
    if (status === "muted" || status === "allowed")
      params.set("dismissed", "true");
    if (source) params.set("source", source);
    if (networkId !== "") params.set("network_id", String(networkId));
    if (search) params.set("search", search);
    const qs = params.toString();
    const token = useAuthStore.getState().token;
    const res = await fetch(
      `/api/alerts/export/${format}${qs ? `?${qs}` : ""}`,
      { headers: token ? { Authorization: `Bearer ${token}` } : {} },
    );
    if (!res.ok) {
      toast.error(`Export failed: ${res.statusText}`);
      return;
    }
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `alerts.${format}`;
    a.click();
    URL.revokeObjectURL(a.href);
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
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className="ml-auto flex items-center gap-1 rounded px-1.5 py-0.5 hover:text-foreground transition-colors"
                title="Export current view"
              >
                <Download className="h-3 w-3" />
                Export
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={() => void exportAlerts("csv")}>
                CSV
              </DropdownMenuItem>
              <DropdownMenuItem onClick={() => void exportAlerts("pdf")}>
                PDF
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>

        {/* Bulk action bar */}
        {selectedIds.size > 0 && (
          <div className="flex items-center gap-2 rounded-md border border-border bg-card px-2 py-1.5 text-xs">
            <span className="text-muted-foreground">
              {selectedIds.size} selected
            </span>
            <Button
              variant="outline"
              size="sm"
              className="h-6 px-2 text-xs"
              onClick={() => setBulkAllowOpen(true)}
            >
              Allow
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-6 px-2 text-xs"
              onClick={() => setBulkMuteOpen(true)}
            >
              Mute
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="h-6 px-2 text-xs text-destructive"
              onClick={() => setBulkDeleteOpen(true)}
            >
              Delete
            </Button>
            <button
              type="button"
              onClick={clearSelection}
              className="ml-auto text-muted-foreground hover:text-foreground transition-colors"
            >
              Clear
            </button>
          </div>
        )}
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
              <input
                type="checkbox"
                aria-label={`Select alert ${alert.id}`}
                checked={selectedIds.has(alert.id)}
                onChange={() => toggleSelected(alert.id)}
                onClick={(e) => e.stopPropagation()}
                className="h-3.5 w-3.5 shrink-0 rounded border-border/50 bg-background"
              />
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

      <AcceptModal
        alertIds={[...selectedIds]}
        open={bulkAllowOpen}
        onOpenChange={setBulkAllowOpen}
        networks={networks.data?.networks ?? []}
        onSuccess={clearSelection}
      />
      <DismissModal
        alertIds={[...selectedIds]}
        open={bulkMuteOpen}
        onOpenChange={setBulkMuteOpen}
        onSuccess={clearSelection}
      />
      <DeleteConfirmModal
        alertCount={selectedIds.size}
        severityCounts={selectedSeverityCounts}
        open={bulkDeleteOpen}
        onOpenChange={setBulkDeleteOpen}
        onConfirm={() =>
          bulkDelete.mutate(
            { alert_ids: [...selectedIds] },
            {
              onSuccess: () => {
                toast.success(`${selectedIds.size} alerts deleted`);
                setBulkDeleteOpen(false);
                clearSelection();
              },
              onError: (e) => toast.error(e.message),
            },
          )
        }
      />
    </div>
  );
}
