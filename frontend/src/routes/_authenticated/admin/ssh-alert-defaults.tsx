import { createFileRoute } from "@tanstack/react-router";

import { SshAlertDefaultsPage } from "@/features/admin/components/SshAlertDefaultsPage";

export const Route = createFileRoute("/_authenticated/admin/ssh-alert-defaults")({
  component: SshAlertDefaultsPage,
});
