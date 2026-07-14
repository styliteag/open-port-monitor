import { createFileRoute, Link } from "@tanstack/react-router";

import { ErrorState } from "@/components/data-display/ErrorState";
import { LoadingState } from "@/components/data-display/LoadingState";
import { SeverityBadge } from "@/components/data-display/SeverityBadge";
import { ThreatPulseChart } from "@/features/dashboard/components/ThreatPulseChart";
import { useAlertTrend } from "@/features/dashboard/hooks/useDashboardData";
import { useExecutiveOverview } from "@/features/overview/hooks/useExecutiveOverview";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/overview")({
  component: OverviewPage,
});

const STATUS_STYLES: Record<string, { dot: string; label: string }> = {
  red: { dot: "bg-red-500", label: "Critical findings" },
  amber: { dot: "bg-orange-500", label: "Needs attention" },
  green: { dot: "bg-emerald-500", label: "OK" },
};

/** Read-only executive status page (ADR 0005). */
function OverviewPage() {
  const overview = useExecutiveOverview();
  const trend = useAlertTrend();

  if (overview.isLoading) return <LoadingState rows={8} />;
  if (overview.error)
    return (
      <ErrorState
        message={overview.error.message}
        onRetry={overview.refetch}
      />
    );

  const data = overview.data;
  if (!data) return <ErrorState message="No overview data" />;

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-strong text-foreground">
            Security Overview
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            {data.open_alerts === 0
              ? "No open alerts across all networks."
              : `${data.open_alerts} open ${data.open_alerts === 1 ? "alert" : "alerts"} across all networks.`}{" "}
            {data.handled_alerts_30d} handled in the last 30 days.
          </p>
        </div>
      </div>

      {/* Traffic lights per network */}
      <div className="rounded-lg border border-border bg-card">
        {data.networks.length === 0 && (
          <p className="p-6 text-sm text-muted-foreground">
            No networks configured yet.
          </p>
        )}
        {data.networks.map((network) => {
          const style = STATUS_STYLES[network.status] ?? STATUS_STYLES.green;
          return (
            <div
              key={network.network_id}
              className="flex items-center gap-4 border-b border-border px-5 py-3.5 last:border-b-0"
            >
              <span className={cn("h-3 w-3 shrink-0 rounded-full", style.dot)} />
              <span className="min-w-0 flex-1 truncate text-sm font-emphasis text-foreground">
                {network.name}
              </span>
              <span className="text-xs text-muted-foreground">
                {network.status === "green"
                  ? "OK"
                  : `${network.open_critical > 0 ? `${network.open_critical} critical` : ""}${
                      network.open_critical > 0 && network.open_high > 0
                        ? ", "
                        : ""
                    }${network.open_high > 0 ? `${network.open_high} high` : ""}`}
              </span>
            </div>
          );
        })}
      </div>

      {/* Risk trend */}
      {trend.data && <ThreatPulseChart data={trend.data.data} />}

      {/* Top risks */}
      <div className="rounded-lg border border-border bg-card p-5">
        <h3 className="mb-3 text-sm font-strong text-foreground">
          Top open risks
        </h3>
        {data.top_risks.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Nothing open — all clear.
          </p>
        ) : (
          <ol className="space-y-2">
            {data.top_risks.map((risk) => (
              <li key={risk.alert_id} className="flex items-center gap-3">
                <SeverityBadge severity={risk.severity} />
                <Link
                  to="/alerts/$alertId"
                  params={{ alertId: String(risk.alert_id) }}
                  className="min-w-0 flex-1 truncate text-sm text-foreground hover:text-primary transition-colors"
                >
                  {risk.message}
                </Link>
                <span className="shrink-0 font-mono text-xs text-muted-foreground">
                  {risk.ip}
                  {risk.port ? `:${risk.port}` : ""}
                </span>
                {risk.network_name && (
                  <span className="shrink-0 text-xs text-muted-foreground">
                    {risk.network_name}
                  </span>
                )}
              </li>
            ))}
          </ol>
        )}
      </div>
    </div>
  );
}
