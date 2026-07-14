import { createFileRoute } from "@tanstack/react-router";
import { Bell } from "lucide-react";

import { EmptyState } from "@/components/data-display/EmptyState";

export const Route = createFileRoute("/_authenticated/alerting")({
  component: AlertingPage,
});

function AlertingPage() {
  return (
    <EmptyState
      icon={Bell}
      title="Alerting"
      message="Configuration hub bundling alert rules, severity rules, and SSH alert defaults. Built in UI v3 phase 4."
    />
  );
}
