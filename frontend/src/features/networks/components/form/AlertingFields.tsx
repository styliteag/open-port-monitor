import { useFormContext } from "react-hook-form";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { SshAlertOverrides } from "../SshAlertOverrides";
import type { NetworkFormData } from "../networkFormSchema";

/** Step/tab "Alerting": recipients, SSH probe, per-network SSH overrides. */
export function AlertingFields() {
  const { register } = useFormContext<NetworkFormData>();

  return (
    <fieldset className="space-y-3">
      <legend className="text-xs font-strong uppercase tracking-wider text-muted-foreground">
        Alerting
      </legend>
      <div>
        <Label htmlFor="email_recipients">Alert Email Recipients</Label>
        <Input
          id="email_recipients"
          {...register("email_recipients")}
          placeholder="admin@example.com, ..."
        />
        <p className="mt-0.5 text-[10px] text-muted-foreground">
          Comma-separated emails
        </p>
      </div>

      <div className="rounded-md border border-border/40 bg-card/40 p-3">
        <label className="flex items-center gap-2 text-sm font-emphasis">
          <input
            type="checkbox"
            className="h-4 w-4 rounded border-border/50 bg-background"
            {...register("ssh_probe_enabled")}
          />
          Run SSH probe on open ports
        </label>
        <p className="mt-0.5 text-[11px] text-muted-foreground">
          When enabled (default), the scanner runs ssh-audit and nmap
          ssh-auth-methods against any discovered SSH service after the port
          scan. Uncheck to skip all SSH probing for this network — no SSH
          findings, banners, or cipher data will be recorded and no SSH alerts
          will fire.
        </p>
      </div>

      <SshAlertOverrides />
    </fieldset>
  );
}
