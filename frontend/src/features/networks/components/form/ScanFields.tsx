import { useEffect } from "react";
import { useFormContext, useWatch } from "react-hook-form";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { useScanners } from "@/features/dashboard/hooks/useDashboardData";
import { useNseProfiles } from "@/features/nse/hooks/useNse";
import { computeScanEstimate } from "@/lib/scan-estimate";
import type { ScanPhase } from "@/lib/types";
import { GvmConfigSection } from "../GvmConfigSection";
import { NucleiSettings } from "../NucleiSettings";
import { PhaseCards } from "../PhaseCards";
import type { NetworkFormData } from "../networkFormSchema";

const RATE_PRESETS = [
  { label: "Slow", value: 100, desc: "Safe for production" },
  { label: "Normal", value: 1000, desc: "Balanced" },
  { label: "Fast", value: 10000, desc: "Aggressive" },
  { label: "Max", value: 100000, desc: "Lab/isolated only" },
];

interface ScanFieldsProps {
  phases: ScanPhase[] | null;
  onPhasesChange: (phases: ScanPhase[] | null) => void;
  gvmScanConfig: string;
  onGvmScanConfigChange: (value: string) => void;
  gvmPortList: string;
  onGvmPortListChange: (value: string) => void;
}

/**
 * Step/tab "Scan": scanner selection, ports, rate/timeouts, phases, and
 * optional vulnerability scanning (NSE/nuclei or GVM depending on the
 * scanner type). Invalid combinations are impossible to select — Greenbone
 * hides phases/NSE/nuclei/rate and shows the GVM block instead.
 */
export function ScanFields({
  phases,
  onPhasesChange,
  gvmScanConfig,
  onGvmScanConfigChange,
  gvmPortList,
  onGvmPortListChange,
}: ScanFieldsProps) {
  const {
    register,
    setValue,
    control,
    formState: { errors },
  } = useFormContext<NetworkFormData>();
  const scanners = useScanners();
  const profiles = useNseProfiles();

  const watchedCidr = useWatch({ control, name: "cidr" }) ?? "";
  const watchedPortSpec = useWatch({ control, name: "port_spec" }) ?? "";
  const watchedRate = useWatch({ control, name: "scan_rate" }) ?? 1000;
  const watchedScannerType = useWatch({ control, name: "scanner_type" });
  const watchedScannerId = Number(useWatch({ control, name: "scanner_id" }) ?? 0);
  const watchedNseProfileId = useWatch({ control, name: "nse_profile_id" });
  const watchedNucleiEnabled =
    useWatch({ control, name: "nuclei_enabled" }) ?? false;
  const isGreenbone = watchedScannerType === "greenbone";

  const vulnEnabled = (phases ?? []).some(
    (p) => p.name === "vulnerability" && p.enabled,
  );
  const vulnersProfileId = (profiles.data?.profiles ?? []).find(
    (p) => p.name === "Vulners CVE Lookup",
  )?.id;

  useEffect(() => {
    if (vulnEnabled && !watchedNseProfileId && vulnersProfileId) {
      setValue("nse_profile_id", vulnersProfileId);
    }
  }, [vulnEnabled, watchedNseProfileId, vulnersProfileId, setValue]);

  const estimate = computeScanEstimate(
    watchedCidr,
    watchedPortSpec,
    watchedRate,
  );

  return (
    <div className="space-y-4">
      {/* ── Scanner Configuration ── */}
      <fieldset className="space-y-3">
        <legend className="text-xs font-strong uppercase tracking-wider text-muted-foreground">
          Scanner
        </legend>
        <div
          className={
            isGreenbone ? "grid grid-cols-2 gap-3" : "grid grid-cols-3 gap-3"
          }
        >
          <div>
            <Label htmlFor="scanner_id">Scanner</Label>
            <Select id="scanner_id" {...register("scanner_id")}>
              <option value="">Select scanner...</option>
              {(scanners.data?.scanners ?? []).map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </Select>
            {errors.scanner_id && (
              <p className="mt-1 text-xs text-destructive">
                {errors.scanner_id.message}
              </p>
            )}
          </div>
          <div>
            <Label htmlFor="scanner_type">Type</Label>
            <Select id="scanner_type" {...register("scanner_type")}>
              <option value="masscan">Masscan</option>
              <option value="nmap">Nmap</option>
              <option value="greenbone">Greenbone (GVM)</option>
            </Select>
          </div>
          {!isGreenbone && (
            <div>
              <Label htmlFor="scan_protocol">Protocol</Label>
              <Select id="scan_protocol" {...register("scan_protocol")}>
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
                <option value="both">Both</option>
              </Select>
            </div>
          )}
        </div>

        {isGreenbone && (
          <GvmConfigSection
            scannerId={watchedScannerId}
            scanConfig={gvmScanConfig}
            onScanConfigChange={onGvmScanConfigChange}
            portList={gvmPortList}
            onPortListChange={onGvmPortListChange}
          />
        )}

        {/* Port specification (ignored when a GVM port list is active) */}
        <div>
          <div className="flex items-baseline justify-between">
            <Label htmlFor="port_spec">Port Specification</Label>
            {isGreenbone && gvmPortList && (
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                Ignored — GVM Port List active
              </span>
            )}
          </div>
          <Input
            id="port_spec"
            {...register("port_spec")}
            placeholder="1-65535"
            className={`font-mono ${
              isGreenbone && gvmPortList ? "opacity-50" : ""
            }`}
          />
          {errors.port_spec && (
            <p className="mt-1 text-xs text-destructive">
              {errors.port_spec.message}
            </p>
          )}
          {isGreenbone && gvmPortList ? (
            <p className="mt-1 text-[11px] text-muted-foreground">
              Not used for this scan — ports come from GVM Port List{" "}
              <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px]">
                {gvmPortList}
              </code>
              . Clear the port list dropdown above to use this field instead.
            </p>
          ) : isGreenbone ? (
            <p className="mt-1 text-[11px] text-muted-foreground">
              Active: the scanner will use these ports directly (no GVM Port
              List selected).
            </p>
          ) : null}
        </div>

        {!isGreenbone && (
          <>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <Label htmlFor="scan_rate">Rate (pps)</Label>
                <Input
                  id="scan_rate"
                  type="number"
                  {...register("scan_rate")}
                  placeholder="1000"
                />
                <div className="mt-1.5 flex gap-1">
                  {RATE_PRESETS.map((p) => (
                    <button
                      key={p.value}
                      type="button"
                      onClick={() => setValue("scan_rate", p.value)}
                      className={`cursor-pointer rounded px-1.5 py-0.5 text-[10px] transition-colors ${
                        watchedRate === p.value
                          ? "bg-primary text-primary-foreground"
                          : "bg-surface-2 text-text-quaternary hover:text-text-secondary"
                      }`}
                      title={p.desc}
                    >
                      {p.label}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <Label htmlFor="scan_timeout">Scan Timeout (min)</Label>
                <Input
                  id="scan_timeout"
                  type="number"
                  {...register("scan_timeout")}
                  placeholder="60"
                />
                {errors.scan_timeout && (
                  <p className="mt-1 text-xs text-destructive">
                    {errors.scan_timeout.message}
                  </p>
                )}
                <p className="mt-0.5 text-[10px] text-muted-foreground">
                  1 – 1 440
                </p>
              </div>
              <div>
                <Label htmlFor="port_timeout">Port Timeout (ms)</Label>
                <Input
                  id="port_timeout"
                  type="number"
                  {...register("port_timeout")}
                  placeholder="1500"
                />
                {errors.port_timeout && (
                  <p className="mt-1 text-xs text-destructive">
                    {errors.port_timeout.message}
                  </p>
                )}
                <p className="mt-0.5 text-[10px] text-muted-foreground">
                  100 – 30 000
                </p>
              </div>
            </div>
            {estimate.ips > 0 && estimate.ports > 0 && watchedRate > 0 && (
              <div
                className="rounded-md border border-border/50 bg-muted/30 px-3 py-2"
                title={estimate.tooltip}
              >
                <p className="text-xs text-muted-foreground">
                  Est. Runtime:{" "}
                  <span className={`font-emphasis ${estimate.color}`}>
                    {estimate.display}
                  </span>
                  <span className="ml-2 text-[10px]">
                    ({estimate.ips.toLocaleString()} IPs &times;{" "}
                    {estimate.ports.toLocaleString()} ports)
                  </span>
                </p>
              </div>
            )}
          </>
        )}
      </fieldset>

      {/* ── Phases + vulnerability scanning (not applicable to Greenbone) ── */}
      {!isGreenbone && (
        <fieldset className="space-y-3">
          <legend className="text-xs font-strong uppercase tracking-wider text-muted-foreground">
            Phases
          </legend>
          <PhaseCards
            phases={phases}
            onChange={onPhasesChange}
            scannerType={
              watchedScannerType as "masscan" | "nmap" | "greenbone"
            }
          />
          <div>
            <Label htmlFor="nse_profile_id">
              NSE Profile{vulnEnabled ? "" : " (optional)"}
            </Label>
            <Select id="nse_profile_id" {...register("nse_profile_id")}>
              {(profiles.data?.profiles ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </Select>
            <p className="mt-1.5 text-xs text-muted-foreground">
              Defaults to{" "}
              <span className="font-mono text-[11px]">Vulners CVE Lookup</span>{" "}
              (CVE detection via version banners). Pick a more specific profile
              for targeted checks (e.g.{" "}
              <span className="font-mono text-[11px]">Open DNS Resolver</span>).
            </p>
          </div>

          <NucleiSettings enabled={watchedNucleiEnabled} />
        </fieldset>
      )}
    </div>
  );
}
