import { createFileRoute } from "@tanstack/react-router";
import { FileCode } from "lucide-react";

import { EmptyState } from "@/components/data-display/EmptyState";

export const Route = createFileRoute("/_authenticated/scan-templates")({
  component: ScanTemplatesPage,
});

function ScanTemplatesPage() {
  return (
    <EmptyState
      icon={FileCode}
      title="Scan Templates"
      message="Configuration hub bundling NSE profiles, the NSE script library and editor, and the GVM library. Built in UI v3 phase 4."
    />
  );
}
