import { createFileRoute } from "@tanstack/react-router";

import { HostnameLookupPage } from "@/features/admin/components/HostnameLookupPage";

export const Route = createFileRoute("/_authenticated/admin/hostname-lookup")({
  component: HostnameLookupPage,
});
