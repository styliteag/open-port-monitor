import { createFileRoute } from "@tanstack/react-router";

import { GvmLibraryPage } from "@/features/gvm-library/components/GvmLibraryPage";

export const Route = createFileRoute("/_authenticated/admin/gvm-library")({
  component: GvmLibraryPage,
});
