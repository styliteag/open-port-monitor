import { useState } from "react";
import { FormProvider } from "react-hook-form";
import { toast } from "sonner";
import { Check } from "lucide-react";

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
import type { NetworkFormData } from "../networkFormSchema";
import { AlertingFields } from "./AlertingFields";
import { BasicsFields } from "./BasicsFields";
import { ScanFields } from "./ScanFields";
import { ScheduleFields } from "./ScheduleFields";
import { useNetworkFormState } from "./useNetworkForm";

const STEPS = [
  { key: "basics", label: "Basics" },
  { key: "scan", label: "Scan type" },
  { key: "schedule", label: "Schedule" },
  { key: "alerting", label: "Alerting" },
  { key: "review", label: "Review" },
] as const;

type StepKey = (typeof STEPS)[number]["key"];

/** Fields validated before leaving each step (ADR 0004 wizard). */
const STEP_FIELDS: Record<StepKey, (keyof NetworkFormData)[]> = {
  basics: ["name", "cidr"],
  scan: [
    "scanner_id",
    "scanner_type",
    "scan_protocol",
    "port_spec",
    "scan_rate",
    "scan_timeout",
    "port_timeout",
    "nse_profile_id",
    "nuclei_tags",
    "nuclei_exclude_tags",
    "nuclei_timeout",
  ],
  schedule: ["scan_schedule"],
  alerting: ["email_recipients", "ssh_override_version_threshold"],
  review: [],
};

interface NetworkWizardProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Pre-fills all values from this network; submission still creates. */
  cloneSource?: Network;
}

/** Guided network creation: Basics → Scan type → Schedule → Alerting → Review. */
export function NetworkWizard({
  open,
  onOpenChange,
  cloneSource,
}: NetworkWizardProps) {
  const { create } = useNetworkMutations();
  const [stepIndex, setStepIndex] = useState(0);
  const state = useNetworkFormState(cloneSource, { cloneName: true });
  const { form } = state;

  const step = STEPS[stepIndex];
  const isLast = stepIndex === STEPS.length - 1;

  const goNext = async () => {
    const valid = await form.trigger(STEP_FIELDS[step.key]);
    if (valid) setStepIndex((i) => Math.min(i + 1, STEPS.length - 1));
  };

  const goBack = () => setStepIndex((i) => Math.max(i - 1, 0));

  const onSubmit = (data: NetworkFormData) => {
    create.mutate(state.buildPayload(data) as Partial<Network>, {
      onSuccess: () => {
        toast.success("Network created");
        onOpenChange(false);
        form.reset();
        setStepIndex(0);
      },
      onError: (e) => toast.error(e.message),
    });
  };

  const values = form.getValues();

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-4xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {cloneSource
              ? `Clone Network — ${cloneSource.name}`
              : "Add Network"}
          </DialogTitle>
        </DialogHeader>

        {/* Step indicator */}
        <ol className="flex items-center gap-1 text-xs">
          {STEPS.map((s, i) => (
            <li key={s.key} className="flex items-center gap-1">
              {i > 0 && <span className="mx-1 h-px w-4 bg-border" />}
              <span
                className={cn(
                  "flex items-center gap-1.5 rounded-full px-2.5 py-1 transition-colors",
                  i === stepIndex
                    ? "bg-accent text-accent-foreground font-emphasis"
                    : i < stepIndex
                      ? "text-foreground"
                      : "text-muted-foreground",
                )}
              >
                {i < stepIndex && <Check className="h-3 w-3" />}
                {s.label}
              </span>
            </li>
          ))}
        </ol>

        <FormProvider {...form}>
          <form
            onSubmit={form.handleSubmit(onSubmit)}
            className="space-y-4 py-2"
          >
            {/* Panels stay mounted so react-hook-form keeps every input
                registered across steps. */}
            <div hidden={step.key !== "basics"}>
              <BasicsFields />
            </div>
            <div hidden={step.key !== "scan"}>
              <ScanFields
                phases={state.phases}
                onPhasesChange={state.setPhases}
                gvmScanConfig={state.gvmScanConfig}
                onGvmScanConfigChange={state.setGvmScanConfig}
                gvmPortList={state.gvmPortList}
                onGvmPortListChange={state.setGvmPortList}
              />
            </div>
            <div hidden={step.key !== "schedule"}>
              <ScheduleFields />
            </div>
            <div hidden={step.key !== "alerting"}>
              <AlertingFields />
            </div>

            {step.key === "review" && (
              <dl className="grid grid-cols-2 gap-3 rounded-md border border-border/50 bg-card/40 p-4 text-sm">
                <div>
                  <dt className="text-xs text-muted-foreground">Name</dt>
                  <dd className="text-foreground">{values.name}</dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">CIDR</dt>
                  <dd className="font-mono text-foreground">{values.cidr}</dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">Scanner type</dt>
                  <dd className="text-foreground">{values.scanner_type}</dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">Ports</dt>
                  <dd className="font-mono text-foreground">
                    {state.isGreenbone && state.gvmPortList
                      ? `GVM port list: ${state.gvmPortList}`
                      : values.port_spec}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">
                    Vulnerability scanning
                  </dt>
                  <dd className="text-foreground">
                    {state.isGreenbone
                      ? `GVM — ${state.gvmScanConfig}`
                      : [
                          // phases === null → backend default phases, which
                          // include an enabled vulnerability (NSE) phase.
                          (state.phases === null ||
                            state.phases.some(
                              (p) => p.name === "vulnerability" && p.enabled,
                            )) &&
                            "NSE",
                          values.nuclei_enabled && "nuclei",
                        ]
                          .filter(Boolean)
                          .join(" + ") || "off"}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">Schedule</dt>
                  <dd className="font-mono text-foreground">
                    {values.scan_schedule || "manual only"}
                  </dd>
                </div>
                <div className="col-span-2">
                  <dt className="text-xs text-muted-foreground">
                    Alert recipients
                  </dt>
                  <dd className="text-foreground">
                    {values.email_recipients || "global default"}
                  </dd>
                </div>
              </dl>
            )}

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
              >
                Cancel
              </Button>
              {stepIndex > 0 && (
                <Button type="button" variant="outline" onClick={goBack}>
                  Back
                </Button>
              )}
              {!isLast ? (
                <Button type="button" onClick={() => void goNext()}>
                  Next
                </Button>
              ) : (
                <Button type="submit" disabled={create.isPending}>
                  {create.isPending ? "Creating..." : "Create Network"}
                </Button>
              )}
            </DialogFooter>
          </form>
        </FormProvider>
      </DialogContent>
    </Dialog>
  );
}
