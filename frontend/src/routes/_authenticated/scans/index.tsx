import { useMemo, useState } from "react";
import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";

import { LoadingState } from "@/components/data-display/LoadingState";
import { ErrorState } from "@/components/data-display/ErrorState";
import { EmptyState } from "@/components/data-display/EmptyState";
import { StatusBadge } from "@/components/data-display/StatusBadge";
import {
  DataTable,
  type DataTableColumn,
} from "@/components/data-display/DataTable";
import { Select } from "@/components/ui/select";
import { useNetworks } from "@/features/dashboard/hooks/useDashboardData";
import { useScans } from "@/features/scans/hooks/useScans";
import { formatRelativeTime, scanStatusVariant } from "@/lib/utils";
import type { ScanSummary } from "@/lib/types";

interface ScansSearchParams {
  network_id?: number;
}

export const Route = createFileRoute("/_authenticated/scans/")({
  component: ScansPage,
  validateSearch: (search: Record<string, unknown>): ScansSearchParams => ({
    network_id: search.network_id ? Number(search.network_id) : undefined,
  }),
});

function buildColumns(
  networkNames: Map<number, string>,
): DataTableColumn<ScanSummary>[] {
  return [
    {
      key: "id",
      header: "ID",
      render: (scan) => (
        <Link
          to="/scans/$scanId"
          params={{ scanId: String(scan.id) }}
          className="text-sm text-primary hover:text-primary/80 transition-colors"
        >
          #{scan.id}
        </Link>
      ),
    },
    {
      key: "network",
      header: "Network",
      render: (scan) => (
        <Link
          to="/networks/$networkId"
          params={{ networkId: String(scan.network_id) }}
          className="text-sm text-foreground hover:text-primary transition-colors"
        >
          {networkNames.get(scan.network_id) ?? `#${scan.network_id}`}
        </Link>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (scan) => (
        <StatusBadge
          label={scan.status}
          variant={scanStatusVariant(scan.status)}
          dot
        />
      ),
    },
    {
      key: "ports",
      header: "Ports",
      render: (scan) => (
        <span className="text-sm text-foreground">{scan.port_count}</span>
      ),
    },
    {
      key: "trigger",
      header: "Trigger",
      render: (scan) => (
        <span className="text-sm text-muted-foreground capitalize">
          {scan.trigger_type}
        </span>
      ),
    },
    {
      key: "started",
      header: "Started",
      render: (scan) => (
        <span className="text-sm text-muted-foreground">
          {scan.started_at ? formatRelativeTime(scan.started_at) : "-"}
        </span>
      ),
    },
    {
      key: "completed",
      header: "Completed",
      render: (scan) => (
        <span className="text-sm text-muted-foreground">
          {scan.completed_at ? formatRelativeTime(scan.completed_at) : "-"}
        </span>
      ),
    },
  ];
}

function ScansPage() {
  const searchParams = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const [page, setPage] = useState(0);
  const limit = 50;
  const { data, isLoading, error, refetch } = useScans(
    page * limit,
    limit,
    searchParams.network_id,
  );
  const networks = useNetworks();

  const networkNames = useMemo(
    () =>
      new Map(
        (networks.data?.networks ?? []).map((n) => [n.id, n.name] as const),
      ),
    [networks.data],
  );
  const columns = useMemo(() => buildColumns(networkNames), [networkNames]);

  const scanList = data?.scans ?? [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-strong text-foreground">Scan History</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Historical record of all scan operations.
          </p>
        </div>
        <Select
          value={searchParams.network_id ?? ""}
          onChange={(e) => {
            setPage(0);
            void navigate({
              search: {
                network_id: e.target.value ? Number(e.target.value) : undefined,
              },
            });
          }}
          className="w-56"
        >
          <option value="">All networks</option>
          {(networks.data?.networks ?? []).map((n) => (
            <option key={n.id} value={n.id}>
              {n.name}
            </option>
          ))}
        </Select>
      </div>

      {isLoading ? (
        <LoadingState rows={8} />
      ) : error ? (
        <ErrorState message={error.message} onRetry={refetch} />
      ) : scanList.length === 0 ? (
        <EmptyState title="No scans" message="No scans have been run yet." />
      ) : (
        <>
          <DataTable columns={columns} rows={scanList} rowKey={(scan) => scan.id} />

          <div className="flex items-center justify-end gap-2">
            <button
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              className="rounded-md border border-border px-3 py-1 text-sm text-muted-foreground hover:text-foreground disabled:opacity-50 transition-colors"
            >
              Previous
            </button>
            <button
              onClick={() => setPage((p) => p + 1)}
              disabled={scanList.length < limit}
              className="rounded-md border border-border px-3 py-1 text-sm text-muted-foreground hover:text-foreground disabled:opacity-50 transition-colors"
            >
              Next
            </button>
          </div>
        </>
      )}
    </div>
  );
}
