import { useFormContext } from "react-hook-form";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { NetworkFormData } from "../networkFormSchema";

/** Step/tab "Basics": network identity. */
export function BasicsFields() {
  const {
    register,
    formState: { errors },
  } = useFormContext<NetworkFormData>();

  return (
    <fieldset className="space-y-3">
      <legend className="text-xs font-strong uppercase tracking-wider text-muted-foreground">
        Network
      </legend>
      <div className="grid grid-cols-[1fr_1fr] gap-3">
        <div>
          <Label htmlFor="name">Name</Label>
          <Input id="name" {...register("name")} placeholder="Internal LAN" />
          {errors.name && (
            <p className="mt-1 text-xs text-destructive">
              {errors.name.message}
            </p>
          )}
        </div>
        <div>
          <Label htmlFor="cidr">CIDR</Label>
          <Input
            id="cidr"
            {...register("cidr")}
            placeholder="192.168.1.0/24"
            className="font-mono"
          />
          {errors.cidr && (
            <p className="mt-1 text-xs text-destructive">
              {errors.cidr.message}
            </p>
          )}
        </div>
      </div>
    </fieldset>
  );
}
