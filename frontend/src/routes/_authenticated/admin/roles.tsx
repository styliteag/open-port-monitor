import { createFileRoute } from "@tanstack/react-router";

import { RolesPage } from "@/features/admin/components/RolesPage";

export const Route = createFileRoute("/_authenticated/admin/roles")({
  component: RolesPage,
});
