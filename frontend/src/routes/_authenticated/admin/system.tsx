import { createFileRoute } from "@tanstack/react-router";
import { Settings2 } from "lucide-react";

import { EmptyState } from "@/components/data-display/EmptyState";

export const Route = createFileRoute("/_authenticated/admin/system")({
  component: SystemPage,
});

function SystemPage() {
  return (
    <EmptyState
      icon={Settings2}
      title="System"
      message="Administration hub for utilities such as the hostname cache and defaults. Built in UI v3 phase 5."
    />
  );
}
