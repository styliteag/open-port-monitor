import { createFileRoute } from "@tanstack/react-router";

import { HostnameLookupPage } from "@/features/admin/components/HostnameLookupPage";

export const Route = createFileRoute("/_authenticated/admin/system")({
  component: SystemPage,
});

/**
 * Administration hub for system utilities (ADR 0002). Currently hosts the
 * hostname cache; future admin utilities land here as tabs.
 */
function SystemPage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-strong text-foreground">System</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Administrative utilities and caches.
        </p>
      </div>
      <HostnameLookupPage />
    </div>
  );
}
