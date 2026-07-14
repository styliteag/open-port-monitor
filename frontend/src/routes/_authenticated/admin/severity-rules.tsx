import { createFileRoute, redirect } from "@tanstack/react-router";

// UI v3 cut-over: this v2 route permanently redirects to its new home.
export const Route = createFileRoute("/_authenticated/admin/severity-rules")({
  beforeLoad: () => {
    throw redirect({ to: "/alerting", search: { tab: "severity" } });
  },
});
