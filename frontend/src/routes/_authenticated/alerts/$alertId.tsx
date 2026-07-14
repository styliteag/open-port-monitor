import { createFileRoute } from "@tanstack/react-router";

import { AlertsInbox } from "@/features/alerts/components/AlertsInbox";

export const Route = createFileRoute("/_authenticated/alerts/$alertId")({
  component: AlertDetailPage,
});

function AlertDetailPage() {
  const { alertId } = Route.useParams();
  return <AlertsInbox selectedAlertId={Number(alertId)} />;
}
