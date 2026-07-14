import { createFileRoute } from "@tanstack/react-router";

import { AlertsInbox } from "@/features/alerts/components/AlertsInbox";

interface AlertsSearch {
  source?: string;
  search?: string;
}

export const Route = createFileRoute("/_authenticated/alerts/")({
  validateSearch: (search: Record<string, unknown>): AlertsSearch => ({
    source: typeof search.source === "string" ? search.source : undefined,
    search: typeof search.search === "string" ? search.search : undefined,
  }),
  component: AlertsPage,
});

function AlertsPage() {
  const { source, search } = Route.useSearch();
  return <AlertsInbox initialSource={source} initialSearch={search} />;
}
