import { createFileRoute, useNavigate } from "@tanstack/react-router";

import { SshAlertDefaultsPage } from "@/features/admin/components/SshAlertDefaultsPage";
import { AlertRulesPage } from "@/features/alert-rules/components/AlertRulesPage";
import { SeverityRulesPage } from "@/features/severity-rules/components/SeverityRulesPage";
import { cn } from "@/lib/utils";

const TABS = [
  { key: "rules", label: "Alert Rules" },
  { key: "severity", label: "Severity Rules" },
  { key: "ssh", label: "SSH Defaults" },
] as const;

type TabKey = (typeof TABS)[number]["key"];

interface AlertingSearch {
  tab?: TabKey;
}

export const Route = createFileRoute("/_authenticated/alerting")({
  validateSearch: (search: Record<string, unknown>): AlertingSearch => ({
    tab:
      search.tab === "severity" || search.tab === "ssh"
        ? search.tab
        : undefined,
  }),
  component: AlertingPage,
});

/**
 * Configuration hub bundling all alerting policy: allow/critical alert
 * rules, per-OID severity overrides, and the global SSH alert defaults
 * (ADR 0002). Each tab renders the full former standalone page.
 */
function AlertingPage() {
  const { tab } = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const activeTab: TabKey = tab ?? "rules";

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-strong text-foreground">Alerting</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Allow rules, severity overrides, and SSH alert defaults.
        </p>
      </div>

      <div
        role="tablist"
        className="inline-flex gap-0.5 rounded-lg border border-border-subtle bg-surface-2/50 p-[3px] text-xs font-emphasis"
      >
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            role="tab"
            aria-selected={activeTab === t.key}
            onClick={() =>
              void navigate({
                search: { tab: t.key === "rules" ? undefined : t.key },
                replace: true,
              })
            }
            className={cn(
              "cursor-pointer rounded-md border px-3 py-1 transition-colors",
              activeTab === t.key
                ? "border-border-standard bg-surface-3 text-text-primary shadow-sm"
                : "border-transparent text-text-quaternary hover:text-text-secondary",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {activeTab === "rules" && <AlertRulesPage />}
      {activeTab === "severity" && <SeverityRulesPage />}
      {activeTab === "ssh" && <SshAlertDefaultsPage />}
    </div>
  );
}
