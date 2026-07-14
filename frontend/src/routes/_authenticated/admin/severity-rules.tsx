import { createFileRoute } from "@tanstack/react-router";

import { SeverityRulesPage } from "@/features/severity-rules/components/SeverityRulesPage";

export const Route = createFileRoute("/_authenticated/admin/severity-rules")({
  component: SeverityRulesPage,
});
