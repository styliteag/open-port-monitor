import { createFileRoute } from "@tanstack/react-router";

import { NseProfilesPage } from "@/features/nse/components/NseProfilesPage";

export const Route = createFileRoute("/_authenticated/nse/profiles")({
  component: NseProfilesPage,
});
