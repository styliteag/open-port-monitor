import { createFileRoute, useNavigate } from "@tanstack/react-router";

import { GvmLibraryPage } from "@/features/gvm-library/components/GvmLibraryPage";
import { NseLibraryPage } from "@/features/nse/components/NseLibraryPage";
import { NseProfilesPage } from "@/features/nse/components/NseProfilesPage";
import { cn } from "@/lib/utils";

const TABS = [
  { key: "profiles", label: "NSE Profiles" },
  { key: "scripts", label: "NSE Scripts" },
  { key: "gvm", label: "GVM Library" },
] as const;

type TabKey = (typeof TABS)[number]["key"];

interface ScanTemplatesSearch {
  tab?: TabKey;
}

export const Route = createFileRoute("/_authenticated/scan-templates")({
  validateSearch: (search: Record<string, unknown>): ScanTemplatesSearch => ({
    tab:
      search.tab === "scripts" || search.tab === "gvm"
        ? search.tab
        : undefined,
  }),
  component: ScanTemplatesPage,
});

/**
 * Configuration hub bundling everything that defines WHAT a scan checks:
 * NSE profiles, the NSE script library (with editor), and the GVM library
 * (ADR 0002). Each tab renders the full former standalone page.
 */
function ScanTemplatesPage() {
  const { tab } = Route.useSearch();
  const navigate = useNavigate({ from: Route.fullPath });
  const activeTab: TabKey = tab ?? "profiles";

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-strong text-foreground">Scan Templates</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          NSE profiles, NSE scripts, and the GVM scan-config library.
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
                search: { tab: t.key === "profiles" ? undefined : t.key },
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

      {activeTab === "profiles" && <NseProfilesPage />}
      {activeTab === "scripts" && <NseLibraryPage />}
      {activeTab === "gvm" && <GvmLibraryPage />}
    </div>
  );
}
