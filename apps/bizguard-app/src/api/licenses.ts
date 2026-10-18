import { api } from "./client";

export type LicenseStatusValue = "active" | "missing" | "expired" | "revoked" | "confirmation_required";

export interface LicenseCapabilities {
  manualScan: boolean;
  autoMonitor: boolean;
  autoMonitorIntervalMinutes: number | null;
  recentLookbackDays: number;
  maxMessagesPerRun: number;
  maxUrlsPerEmail: number;
  maxAttachmentsPerEmail: number;
  priorityAi: boolean;
  criticalAlerts: boolean;
  monthlyConfirmation: boolean;
  autoSpamCritical: boolean;
  spamActionAudit: boolean;
  trustedSenderAllowlist: boolean;
  priorityRecheck: boolean;
}

export interface LicenseStatus {
  status: LicenseStatusValue;
  plan: string | null;
  planLabel: string | null;
  expiresAt: string | null;
  activatedAt: string | null;
  confirmationRequired: boolean;
  confirmationDueAt: string | null;
  lastConfirmedAt: string | null;
  capabilities: LicenseCapabilities;
  maxActivations: number | null;
  activationCount: number;
  remainingActivations: number;
  capacityFull: boolean;
}

export interface LicenseGateValidation {
  gateToken: string;
  plan: string;
  planLabel: string;
  durationDays: number;
  capabilities: LicenseCapabilities;
  maxActivations: number;
  activationCount: number;
  remainingActivations: number;
  capacityFull: boolean;
  expiresInSeconds: number;
}

export interface LicensePlanInfo {
  plan: string;
  planLabel: string;
  durationDays: number;
  capabilities: LicenseCapabilities;
}

const LICENSE_GATE_TOKEN_KEY = "license_gate_token";

export const licenseGateStorage = {
  get: (): string | null => sessionStorage.getItem(LICENSE_GATE_TOKEN_KEY),
  set: (gateToken: string) => sessionStorage.setItem(LICENSE_GATE_TOKEN_KEY, gateToken),
  clear: () => sessionStorage.removeItem(LICENSE_GATE_TOKEN_KEY),
};

export function hasActiveLicense(license?: LicenseStatus | null): boolean {
  return license?.status === "active";
}

export async function validateLicenseKey(key: string): Promise<LicenseGateValidation> {
  const result = await api.post<LicenseGateValidation>("/licenses/validate-key", { key });
  licenseGateStorage.set(result.gateToken);
  return result;
}

export async function fetchLicenseStatus(): Promise<LicenseStatus> {
  return api.get<LicenseStatus>("/licenses/status");
}

export async function fetchLicensePlans(): Promise<LicensePlanInfo[]> {
  const result = await api.get<{ plans: LicensePlanInfo[] }>("/licenses/plans");
  return result.plans;
}

export async function activateLicenseKey(key: string): Promise<LicenseStatus> {
  const result = await api.post<{ license: LicenseStatus }>("/licenses/activate", { key });
  return result.license;
}

export async function confirmLicenseKey(key: string): Promise<LicenseStatus> {
  const result = await api.post<{ license: LicenseStatus }>("/licenses/confirm", { key });
  return result.license;
}
