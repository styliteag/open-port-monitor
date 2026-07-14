import { createFileRoute, redirect } from "@tanstack/react-router";

// UI v3 cut-over: this v2 route permanently redirects to its new home.
export const Route = createFileRoute("/_authenticated/admin/roles")({
  beforeLoad: () => {
    throw redirect({ to: "/admin/users", search: { tab: "roles" } });
  },
});
