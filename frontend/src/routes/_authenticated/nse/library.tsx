import { createFileRoute } from "@tanstack/react-router";

import { NseLibraryPage } from "@/features/nse/components/NseLibraryPage";

export const Route = createFileRoute("/_authenticated/nse/library")({
  component: NseLibraryPage,
});
