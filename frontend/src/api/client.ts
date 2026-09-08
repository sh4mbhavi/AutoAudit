const API_BASE_URL = import.meta.env.VITE_API_URL as string | undefined;

if (!API_BASE_URL) {
  throw new Error("VITE_API_URL environment variable must be set");
}

type APIErrorPayload = Record<string, unknown> | undefined;

export class APIError extends Error {
  status: number;
  payload?: APIErrorPayload;

  constructor(message: string, status: number, payload?: APIErrorPayload) {
    super(message);
    this.name = "APIError";
    this.status = status;
    this.payload = payload;
  }
}

function getErrorDetail(payload: unknown, fallback: string): string {
  if (
    payload &&
    typeof payload === "object" &&
    "detail" in payload &&
    typeof (payload as { detail?: unknown }).detail === "string"
  ) {
    return (payload as { detail: string }).detail;
  }
  return fallback;
}

function releaseResponse(response: Response): void {
  // Cancel discarded bodies so fetch connections finish even when no caller
  // reads them. Do not await cancellation: a cloned/teed stream can wait for
  // its other consumer, which must not block authentication recovery.
  void response.body?.cancel().catch(() => {});
}

// CSRF bootstrap is shared by simultaneous mutations and never persisted.
let sessionEpoch = 0;
let csrfInFlight: Promise<string> | null = null;
async function csrfToken(): Promise<string> {
  if (!csrfInFlight) {
    csrfInFlight = (async () => {
      const response = await fetch(`${API_BASE_URL}/v1/auth/csrf`, {
        credentials: "include",
        cache: "no-store",
      });
      if (!response.ok) {
        releaseResponse(response);
        throw new APIError(
          "Could not verify this request. Reload and try again.",
          response.status,
        );
      }
      const body = await response.json();
      if (typeof body.csrf_token !== "string" || !body.csrf_token)
        throw new APIError("Invalid request verification response", 403);
      return body.csrf_token as string;
    })();
  }
  try {
    return await csrfInFlight;
  } finally {
    csrfInFlight = null;
  }
}
async function sessionFetch(
  url: string,
  options: RequestInit = {},
  mayRetry = true,
): Promise<Response> {
  const epoch = sessionEpoch;
  const headers = new Headers(options.headers);
  if (
    !["GET", "HEAD", "OPTIONS"].includes(
      (options.method || "GET").toUpperCase(),
    )
  )
    headers.set("X-CSRF-Token", await csrfToken());
  const response = await fetch(url, {
    ...options,
    headers,
    credentials: "include",
  });
  if (
    response.ok &&
    [
      "/auth/login",
      "/auth/logout",
      "/auth/refresh",
      "/auth/users/me/change-password",
    ].some((path) => url.endsWith(path))
  )
    sessionEpoch += 1;
  if (
    response.status === 401 &&
    mayRetry &&
    !["/auth/logout", "/auth/login", "/auth/refresh"].some((path) =>
      url.endsWith(path),
    )
  ) {
    // A different tab may have rotated the cookie while this request was in
    // flight. Probe the current cookie directly, then retry once without loops.
    let current: Response;
    try {
      current = await fetch(`${API_BASE_URL}/v1/auth/users/me`, {
        credentials: "include",
        cache: "no-store",
      });
    } catch {
      return response;
    }
    if (current.ok) {
      releaseResponse(response);
      if (url.endsWith("/auth/users/me")) return current;
      releaseResponse(current);
      return sessionFetch(url, options, false);
    }
    releaseResponse(current);
    if (current.status === 401 && epoch === sessionEpoch)
      window.dispatchEvent(new Event("autoaudit:session-expired"));
  }
  return response;
}

// Helper for making authenticated requests
async function fetchWithAuth<T = any>(
  endpoint: string,
  options: RequestInit = {},
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((options.headers as Record<string, string> | undefined) || {}),
  };

  try {
    const response = await sessionFetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = (await response
        .json()
        .catch(() => ({ detail: response.statusText }))) as Record<
        string,
        unknown
      >;
      throw new APIError(
        getErrorDetail(error, "Request failed"),
        response.status,
        error,
      );
    }

    // Support endpoints that may return 204 No Content.
    if (response.status === 204) {
      return undefined as T;
    }

    return (await response.json()) as T;
  } catch (error: unknown) {
    if (error instanceof APIError) {
      throw error;
    }
    const message = error instanceof Error ? error.message : "Network error";
    throw new APIError(message, 0);
  }
}

// Auth endpoints
export async function login(email: string, password: string): Promise<any> {
  const response = await sessionFetch(`${API_BASE_URL}/v1/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      username: email,
      password,
    }),
  });

  if (!response.ok) {
    const error = (await response
      .json()
      .catch(() => ({ detail: "Login failed" }))) as Record<string, unknown>;
    throw new APIError(
      getErrorDetail(error, "Invalid credentials"),
      response.status,
      error,
    );
  }

  return;
}

export type RegisterPayload = {
  firstName: string;
  lastName: string;
  email: string;
  organizationName: string;
  password: string;
};

export async function register(payload: RegisterPayload): Promise<any> {
  return fetchWithAuth("/v1/auth/register", {
    method: "POST",
    body: JSON.stringify({
      first_name: payload.firstName,
      last_name: payload.lastName,
      email: payload.email,
      organization_name: payload.organizationName,
      password: payload.password,
    }),
  });
}

export async function logout(): Promise<void> {
  await fetchWithAuth("/v1/auth/logout", { method: "POST" });
}
export async function refreshSession(): Promise<void> {
  const rotate = async () => {
    try {
      await fetchWithAuth("/v1/auth/refresh", { method: "POST" });
    } catch (error) {
      if (!(error instanceof APIError) || error.status !== 401) throw error;
      // Another tab may have rotated the shared cookie. Only require reauth if
      // the current cookie also fails, rather than trusting the stale request.
      await getCurrentUser();
    }
  };
  if (navigator.locks)
    await navigator.locks.request("autoaudit-session-refresh", rotate);
  else await rotate();
}

export async function getCurrentUser(): Promise<any> {
  return fetchWithAuth("/v1/auth/users/me");
}

export type UpdateCurrentUserPayload = {
  first_name?: string;
  last_name?: string;
  organization_name?: string;
};

export async function updateCurrentUser(
  payload: UpdateCurrentUserPayload,
): Promise<any> {
  return fetchWithAuth("/v1/auth/users/me", {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export type ChangePasswordPayload = {
  current_password: string;
  new_password: string;
};

export async function changePassword(
  payload: ChangePasswordPayload,
): Promise<any> {
  await fetchWithAuth("/v1/auth/users/me/change-password", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  window.dispatchEvent(new Event("autoaudit:session-expired"));
}

// Contact submissions
export type ContactSubmissionCreatePayload = {
  first_name: string;
  last_name: string;
  email: string;
  phone?: string | null;
  company?: string | null;
  subject: string;
  message: string;
  source?: string;
};

export async function createContactSubmission(
  payload: ContactSubmissionCreatePayload,
): Promise<any> {
  return fetchWithAuth("/v1/contact", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getContactSubmissions(): Promise<any> {
  return fetchWithAuth("/v1/contact/submissions");
}

export async function getContactSubmission(id: string | number): Promise<any> {
  return fetchWithAuth(`/v1/contact/submissions/${id}`);
}

export async function updateContactSubmission(
  id: string | number,
  payload: Record<string, unknown>,
): Promise<any> {
  return fetchWithAuth(`/v1/contact/submissions/${id}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function deleteContactSubmission(
  id: string | number,
): Promise<void> {
  const response = await sessionFetch(
    `${API_BASE_URL}/v1/contact/submissions/${id}`,
    {
      method: "DELETE",
    },
  );

  if (!response.ok) {
    const error = (await response
      .json()
      .catch(() => ({ detail: response.statusText }))) as Record<
      string,
      unknown
    >;
    throw new APIError(
      getErrorDetail(error, "Failed to delete submission"),
      response.status,
      error,
    );
  }
}

export async function getContactNotes(id: string | number): Promise<any> {
  return fetchWithAuth(`/v1/contact/submissions/${id}/notes`);
}

export async function addContactNote(
  id: string | number,
  payload: Record<string, unknown>,
): Promise<any> {
  return fetchWithAuth(`/v1/contact/submissions/${id}/notes`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getContactHistory(id: string | number): Promise<any> {
  return fetchWithAuth(`/v1/contact/submissions/${id}/history`);
}

// Settings endpoints
export async function getSettings(): Promise<any> {
  return fetchWithAuth("/v1/settings");
}

export async function updateSettings(
  data: Record<string, unknown>,
): Promise<any> {
  return fetchWithAuth("/v1/settings", {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

// Platform endpoints
export async function getPlatforms(): Promise<any> {
  return fetchWithAuth("/v1/platforms");
}

// M365 Connection endpoints
export type SharePointConnectionPayload = {
  sharepoint_admin_url?: string | null;
  sharepoint_tenant_id?: string | null;
  sharepoint_certificate_alias?: string | null;
};
export type CreateConnectionPayload = SharePointConnectionPayload & {
  name: string;
  tenant_id: string;
  client_id: string;
  client_secret: string;
};

export type UpdateConnectionPayload = SharePointConnectionPayload & {
  name?: string;
  tenant_id?: string;
  client_id?: string;
  client_secret?: string;
};

export async function getConnections(): Promise<any> {
  return fetchWithAuth("/v1/m365-connections/");
}

export async function createConnection(
  data: CreateConnectionPayload,
): Promise<any> {
  return fetchWithAuth("/v1/m365-connections/", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function updateConnection(
  id: string | number,
  data: UpdateConnectionPayload,
): Promise<any> {
  return fetchWithAuth(`/v1/m365-connections/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function deleteConnection(id: string | number): Promise<void> {
  const response = await sessionFetch(
    `${API_BASE_URL}/v1/m365-connections/${id}`,
    {
      method: "DELETE",
    },
  );

  if (!response.ok) {
    const error = (await response
      .json()
      .catch(() => ({ detail: response.statusText }))) as Record<
      string,
      unknown
    >;
    throw new Error(getErrorDetail(error, "Failed to delete connection"));
  }

  // DELETE returns 204 No Content, so don't try to parse JSON
  return;
}

export async function testConnection(id: string | number): Promise<any> {
  return fetchWithAuth(`/v1/m365-connections/${id}/test`, {
    method: "POST",
  });
}

// Benchmark endpoints
export async function getBenchmarks(): Promise<any> {
  return fetchWithAuth("/v1/benchmarks");
}

// Scan endpoints
export type CreateScanPayload = {
  m365_connection_id: number;
  framework: string;
  benchmark: string;
  version: string;
};

// One item in the readiness breakdown shown on the scan form.
export type ScanReadinessCheck = {
  key: string;
  label: string;
  status: "pass" | "fail" | "warn";
  severity: "critical" | "warning";
  message: string;
};

export type ScanReadinessResponse = {
  ready: boolean;
  summary: string;
  required_permissions: string[];
  missing_permissions: string[];
  unverified_permissions: string[];
  checks: ScanReadinessCheck[];
};

export async function getScans(): Promise<any> {
  return fetchWithAuth("/v1/scans/");
}

export async function getScan(id: string | number): Promise<any> {
  return fetchWithAuth(`/v1/scans/${id}`);
}

export async function cancelScan(id: string | number): Promise<{ id: number | string; status: string; message: string }> {
  return fetchWithAuth(`/v1/scans/${id}/cancel`, { method: "POST" });
}

export async function createScan(data: CreateScanPayload): Promise<any> {
  return fetchWithAuth("/v1/scans/", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function getScanReadiness(params: {
  m365_connection_id: number;
  framework: string;
  benchmark: string;
  version: string;
}): Promise<ScanReadinessResponse> {
  // Readiness is a lightweight GET request because it only validates the selected connection and benchmark. It does not create or start a scan.
  const search = new URLSearchParams({
    m365_connection_id: String(params.m365_connection_id),
    framework: params.framework,
    benchmark: params.benchmark,
    version: params.version,
  });

  return fetchWithAuth(`/v1/scans/readiness?${search.toString()}`);
}

export async function deleteScan(id: string | number): Promise<void> {
  const response = await sessionFetch(`${API_BASE_URL}/v1/scans/${id}`, {
    method: "DELETE",
  });

  if (!response.ok) {
    const error = (await response
      .json()
      .catch(() => ({ detail: response.statusText }))) as Record<
      string,
      unknown
    >;
    throw new Error(getErrorDetail(error, "Failed to delete scan"));
  }

  // DELETE returns 204 No Content, so don't try to parse JSON
  return;
}

// Evidence scanner endpoints
export async function getEvidenceStrategies(): Promise<any> {
  // Frontend -> Backend
  // GET /v1/evidence/strategies
  //
  // Returns an array of strategy objects, e.g.
  // [{ name, description, category, severity, evidence_types }, ...]
  // (see backend-api/app/api/v1/evidence.py -> strategies()).
  return fetchWithAuth("/v1/evidence/strategies");
}

export type ScanEvidenceParams = {
  strategyName: string;
  file: File | Blob;
};

export async function scanEvidence({
  strategyName,
  file,
}: ScanEvidenceParams): Promise<any> {
  // Frontend -> Backend
  // POST /v1/evidence/scan (multipart/form-data)
  //
  // This uploads an evidence file and tells the backend which strategy to run.
  // The server derives the user from the authenticated session.
  // Backend returns a JSON payload that the UI renders in the Results section.
  if (!strategyName) {
    throw new Error("Strategy is required");
  }
  if (!file) {
    throw new Error("Evidence file is required");
  }

  const formData = new FormData();
  // These field names must match the FastAPI endpoint signature in:
  // backend-api/app/api/v1/evidence.py -> scan(...)
  formData.append("strategy_name", strategyName);
  formData.append("evidence", file);

  const headers: Record<string, string> = {};

  const response = await sessionFetch(`${API_BASE_URL}/v1/evidence/scan`, {
    method: "POST",
    headers,
    body: formData,
  });

  if (!response.ok) {
    // The backend may respond with JSON (FastAPI error) or plain text.
    // We parse best-effort and throw APIError so callers can display a message.
    const raw = await response.text().catch(() => "");
    try {
      const error = (
        raw ? JSON.parse(raw) : { detail: response.statusText }
      ) as Record<string, unknown>;
      throw new APIError(
        getErrorDetail(error, "Scan failed"),
        response.status,
        error,
      );
    } catch {
      throw new APIError(raw || "Scan failed", response.status);
    }
  }

  return response.json();
}

export function getEvidenceReportUrl(filename: string): string {
  // Frontend helper to build a direct download URL for a generated report.
  // Backend endpoint: GET /v1/evidence/reports/{filename}
  if (!filename) return "";
  return `${API_BASE_URL}/v1/evidence/reports/${encodeURIComponent(filename)}`;
}

export async function downloadEvidenceReport(filename: string): Promise<void> {
  // Downloads the report using the authenticated browser session.
  if (!filename) return;

  const headers: Record<string, string> = {};

  const response = await sessionFetch(
    `${API_BASE_URL}/v1/evidence/reports/${encodeURIComponent(filename)}`,
    { method: "GET", headers },
  );

  if (!response.ok) {
    throw new Error(`Download failed: ${response.status}`);
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
}
