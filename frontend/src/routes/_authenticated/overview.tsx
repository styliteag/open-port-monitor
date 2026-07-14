import { createFileRoute } from "@tanstack/react-router";
import { Gauge } from "lucide-react";

import { EmptyState } from "@/components/data-display/EmptyState";

export const Route = createFileRoute("/_authenticated/overview")({
  component: OverviewPage,
});

function OverviewPage() {
  return (
    <EmptyState
      icon={Gauge}
      title="Executive Overview"
      message="Read-only status page with per-network traffic lights, risk trend, and top risks. Built in UI v3 phase 5 (ADR 0005)."
    />
  );
}
