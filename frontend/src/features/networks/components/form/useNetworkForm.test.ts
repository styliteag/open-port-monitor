import { describe, it, expect } from "vitest";

import type { ScanPhase } from "@/lib/types";
import type { NetworkFormData } from "../networkFormSchema";
import {
  buildNetworkDefaults,
  buildNetworkPayload,
  buildSshOverridesPayload,
  readSshOverrides,
} from "./useNetworkForm";

function formData(overrides: Partial<NetworkFormData> = {}): NetworkFormData {
  return {
    name: "Test",
    cidr: "10.0.0.0/24",
    port_spec: "1-65535",
    scanner_id: 1,
    scanner_type: "masscan",
    scan_protocol: "tcp",
    scan_rate: 1000,
    scan_timeout: 60,
    port_timeout: 1500,
    gvm_keep_reports: true,
    ssh_probe_enabled: true,
    nuclei_enabled: false,
    nuclei_tags: "cve",
    nuclei_exclude_tags: "dos",
    nuclei_sni_enabled: false,
    email_recipients: "",
    ssh_override_insecure_auth: "inherit",
    ssh_override_weak_cipher: "inherit",
    ssh_override_weak_kex: "inherit",
    ssh_override_outdated_version: "inherit",
    ssh_override_config_regression: "inherit",
    ssh_override_version_threshold: "",
    ...overrides,
  } as NetworkFormData;
}

const baseCtx = {
  isGreenbone: false,
  phases: null,
  gvmScanConfig: "Full and fast",
  gvmPortList: "",
  sourceAlertConfig: null,
};

describe("buildNetworkPayload", () => {
  it("converts timeout minutes to seconds", () => {
    const payload = buildNetworkPayload(formData({ scan_timeout: 90 }), baseCtx);
    expect(payload.scan_timeout).toBe(5400);
  });

  it("nulls GVM fields for non-greenbone scanners", () => {
    const payload = buildNetworkPayload(formData(), baseCtx);
    expect(payload.gvm_scan_config).toBeNull();
    expect(payload.gvm_port_list).toBeNull();
    expect(payload.gvm_alert_severity).toBeNull();
  });

  it("nulls phases and nuclei for greenbone", () => {
    const phases: ScanPhase[] = [
      { name: "port_scan", enabled: true, tool: "masscan", config: {} },
    ];
    const payload = buildNetworkPayload(
      formData({ scanner_type: "greenbone", nuclei_enabled: true }),
      { ...baseCtx, isGreenbone: true, phases, gvmPortList: "All TCP" },
    );
    expect(payload.phases).toBeNull();
    expect(payload.nuclei_enabled).toBe(false);
    expect(payload.nuclei_tags).toBeNull();
    expect(payload.gvm_scan_config).toBe("Full and fast");
    expect(payload.gvm_port_list).toBe("All TCP");
  });

  it("patches the port_scan phase tool to the scanner type", () => {
    const phases: ScanPhase[] = [
      { name: "port_scan", enabled: true, tool: "masscan", config: {} },
      { name: "vulnerability", enabled: true, tool: "nmap_nse", config: {} },
    ];
    const payload = buildNetworkPayload(
      formData({ scanner_type: "nmap" }),
      { ...baseCtx, phases },
    );
    const result = payload.phases as ScanPhase[];
    expect(result[0].tool).toBe("nmap");
    expect(result[1].tool).toBe("nmap_nse");
  });

  it("clears nuclei config when nuclei is disabled", () => {
    const payload = buildNetworkPayload(
      formData({ nuclei_enabled: false, nuclei_tags: "cve" }),
      baseCtx,
    );
    expect(payload.nuclei_enabled).toBe(false);
    expect(payload.nuclei_tags).toBeNull();
    expect(payload.nuclei_timeout).toBeNull();
  });

  it("keeps nuclei config and converts its timeout when enabled", () => {
    const payload = buildNetworkPayload(
      formData({ nuclei_enabled: true, nuclei_timeout: 120 }),
      baseCtx,
    );
    expect(payload.nuclei_enabled).toBe(true);
    expect(payload.nuclei_tags).toBe("cve");
    expect(payload.nuclei_timeout).toBe(7200);
  });

  it("builds alert_config from recipients + non-inherit SSH overrides", () => {
    const payload = buildNetworkPayload(
      formData({
        email_recipients: "a@x.de, b@x.de",
        ssh_override_weak_cipher: "off",
        ssh_override_insecure_auth: "on",
      }),
      baseCtx,
    );
    expect(payload.alert_config).toEqual({
      email_recipients: ["a@x.de", "b@x.de"],
      ssh_weak_cipher: false,
      ssh_insecure_auth: true,
    });
  });

  it("carries unmanaged alert_config keys, drops managed ones", () => {
    const payload = buildNetworkPayload(formData(), {
      ...baseCtx,
      sourceAlertConfig: {
        smtp_override: "custom",
        email_recipients: ["old@x.de"],
        ssh_weak_kex: true,
      },
    });
    // inherit → managed keys removed; unmanaged key rides along
    expect(payload.alert_config).toEqual({ smtp_override: "custom" });
  });

  it("returns null alert_config when nothing is set", () => {
    const payload = buildNetworkPayload(formData(), baseCtx);
    expect(payload.alert_config).toBeNull();
  });
});

describe("readSshOverrides / buildSshOverridesPayload", () => {
  it("round-trips tri-state values", () => {
    const config = { ssh_weak_cipher: false, ssh_insecure_auth: true };
    const fields = readSshOverrides(config);
    expect(fields.ssh_override_weak_cipher).toBe("off");
    expect(fields.ssh_override_insecure_auth).toBe("on");
    expect(fields.ssh_override_weak_kex).toBe("inherit");

    const back = buildSshOverridesPayload(formData(fields));
    expect(back).toEqual(config);
  });
});

describe("buildNetworkDefaults", () => {
  it("prefixes the name when cloning", () => {
    const defaults = buildNetworkDefaults(
      {
        id: 1,
        name: "Office",
        cidr: "10.0.0.0/24",
        port_spec: "1-1000",
        scanner_id: 2,
        scanner_type: "nmap",
        scan_protocol: "tcp",
        scan_timeout: 3600,
        alert_config: null,
      } as never,
      { cloneName: true },
    );
    expect(defaults.name).toBe("Copy of Office");
    // seconds → minutes
    expect(defaults.scan_timeout).toBe(60);
  });

  it("provides safe create defaults without a source", () => {
    const defaults = buildNetworkDefaults(undefined);
    expect(defaults.scanner_type).toBe("masscan");
    expect(defaults.port_spec).toBe("1-65535");
    expect(defaults.ssh_override_weak_cipher).toBe("inherit");
  });
});
