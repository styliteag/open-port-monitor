import { useFormContext, useWatch } from "react-hook-form";

import { ScheduleBuilder } from "../ScheduleBuilder";
import type { NetworkFormData } from "../networkFormSchema";

/** Step/tab "Schedule": recurring scan schedule. */
export function ScheduleFields() {
  const { setValue, control } = useFormContext<NetworkFormData>();
  const watchedSchedule = useWatch({ control, name: "scan_schedule" }) ?? "";

  return (
    <fieldset className="space-y-3">
      <legend className="text-xs font-strong uppercase tracking-wider text-muted-foreground">
        Schedule
      </legend>
      <ScheduleBuilder
        value={watchedSchedule}
        onChange={(v) => setValue("scan_schedule", v)}
      />
    </fieldset>
  );
}
