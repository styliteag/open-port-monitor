import { useState } from "react";
import { FormProvider } from "react-hook-form";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { useNetworkMutations } from "@/features/networks/hooks/useNetworkDetail";
import type { Network } from "@/lib/types";
import { cn } from "@/lib/utils";
import { AlertingFields } from "./form/AlertingFields";
import { BasicsFields } from "./form/BasicsFields";
import { ScanFields } from "./form/ScanFields";
import { ScheduleFields } from "./form/ScheduleFields";
import { useNetworkFormState } from "./form/useNetworkForm";
import type { NetworkFormData } from "./networkFormSchema";

const TABS = [
  { key: "basics", label: "Basics" },
  { key: "scan", label: "Scan" },
  { key: "schedule", label: "Schedule" },
  { key: "alerting", label: "Alerting" },
] as const;

type TabKey = (typeof TABS)[number]["key"];

/** Maps a form field to the tab that renders it (error auto-switch). */
const FIELD_TO_TAB: Record<string, TabKey> = {
  name: "basics",
  cidr: "basics",
  scan_schedule: "schedule",
  email_recipients: "alerting",
  ssh_probe_enabled: "alerting",
  ssh_override_version_threshold: "alerting",
};

interface NetworkFormProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** The network being edited. Creation/cloning lives in NetworkWizard. */
  network: Network;
}

/**
 * Tab editor for existing networks (ADR 0004): the same four groups as the
 * creation wizard, but with direct access to any section — no step sequence.
 */
export function NetworkForm({ open, onOpenChange, network }: NetworkFormProps) {
  const { update } = useNetworkMutations();
  const [activeTab, setActiveTab] = useState<TabKey>("basics");
  const state = useNetworkFormState(network);
  const { form } = state;

  const onSubmit = (data: NetworkFormData) => {
    update.mutate(
      { id: network.id, ...(state.buildPayload(data) as Partial<Network>) },
      {
        onSuccess: () => {
          toast.success("Network updated");
          onOpenChange(false);
        },
        onError: (e) => toast.error(e.message),
      },
    );
  };

  // When zod rejects the submit, jump to the tab holding the first bad field.
  const onInvalid = (fieldErrors: Record<string, unknown>) => {
    const firstErrorField = Object.keys(fieldErrors)[0];
    if (firstErrorField) {
      setActiveTab(FIELD_TO_TAB[firstErrorField] ?? "scan");
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Edit Network — {network.name}</DialogTitle>
        </DialogHeader>
        <FormProvider {...form}>
          <form
            onSubmit={form.handleSubmit(onSubmit, onInvalid)}
            className="space-y-4 py-2"
          >
            <div
              role="tablist"
              className="inline-flex gap-0.5 rounded-lg border border-border-subtle bg-surface-2/50 p-[3px] text-xs font-emphasis"
            >
              {TABS.map((tab) => (
                <button
                  key={tab.key}
                  type="button"
                  role="tab"
                  aria-selected={activeTab === tab.key}
                  onClick={() => setActiveTab(tab.key)}
                  className={cn(
                    "cursor-pointer rounded-md border px-3 py-1 transition-colors",
                    activeTab === tab.key
                      ? "border-border-standard bg-surface-3 text-text-primary shadow-sm"
                      : "border-transparent text-text-quaternary hover:text-text-secondary",
                  )}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            {/* Panels stay mounted (hidden attribute) so react-hook-form
                keeps every input registered across tab switches. */}
            <div role="tabpanel" hidden={activeTab !== "basics"}>
              <BasicsFields />
            </div>
            <div role="tabpanel" hidden={activeTab !== "scan"}>
              <ScanFields
                phases={state.phases}
                onPhasesChange={state.setPhases}
                gvmScanConfig={state.gvmScanConfig}
                onGvmScanConfigChange={state.setGvmScanConfig}
                gvmPortList={state.gvmPortList}
                onGvmPortListChange={state.setGvmPortList}
              />
            </div>
            <div role="tabpanel" hidden={activeTab !== "schedule"}>
              <ScheduleFields />
            </div>
            <div role="tabpanel" hidden={activeTab !== "alerting"}>
              <AlertingFields />
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={update.isPending}>
                {update.isPending ? "Saving..." : "Save"}
              </Button>
            </DialogFooter>
          </form>
        </FormProvider>
      </DialogContent>
    </Dialog>
  );
}
