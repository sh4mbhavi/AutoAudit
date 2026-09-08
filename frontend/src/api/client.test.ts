import { test, expect, vi, beforeEach, afterEach } from "vitest";
import * as api from "./client";
let response: Response;
const json = (status: number, body?: unknown) =>
  new Response(body === undefined ? null : JSON.stringify(body), { status });
beforeEach(() => {
  response = json(200, { id: 1 });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string) =>
      url.endsWith("/auth/csrf")
        ? json(200, { csrf_token: "synthetic-csrf" })
        : response.clone(),
    ),
  );
});
afterEach(() => vi.unstubAllGlobals());
test("APIError preserves status and payload", () => {
  const e = new api.APIError("message", 403, { detail: "denied" });
  expect(e).toBeInstanceOf(Error);
  expect(e.name).toBe("APIError");
  expect(e.status).toBe(403);
  expect(e.payload).toEqual({ detail: "denied" });
});
test("report URLs encode filenames", () => {
  expect(api.getEvidenceReportUrl("")).toBe("");
  expect(api.getEvidenceReportUrl("a b.pdf")).toMatch(/a%20b.pdf$/);
});
test("GET sends only the cookie credentials", async () => {
  await api.getCurrentUser();
  const [, options] = vi.mocked(fetch).mock.calls[0];
  expect(options?.credentials).toBe("include");
  expect(new Headers(options?.headers).has("Authorization")).toBe(false);
  expect(fetch).toHaveBeenCalledTimes(1);
});
test("login bootstraps CSRF and returns no token", async () => {
  response = json(204);
  expect(await api.login("user@example.com", "password")).toBeUndefined();
  const [url, options] = vi.mocked(fetch).mock.calls[1];
  expect(url).toMatch(/\/auth\/login$/);
  expect(options?.credentials).toBe("include");
  const headers = new Headers(options?.headers);
  expect(headers.get("X-CSRF-Token")).toBe("synthetic-csrf");
  expect(headers.get("Content-Type")).toBe("application/x-www-form-urlencoded");
  expect(headers.has("Authorization")).toBe(false);
  const body = new URLSearchParams(options?.body as string);
  expect(body.get("username")).toBe("user@example.com");
  expect(body.get("password")).toBe("password");
});
test.each([
  ["logout", () => api.logout()],
  [
    "register",
    () =>
      api.register({
        firstName: "A",
        lastName: "B",
        email: "x@example.com",
        organizationName: "C",
        password: "password",
      }),
  ],
  ["profile", () => api.updateCurrentUser({ first_name: "A" })],
  ["delete connection", () => api.deleteConnection(1)],
  ["delete scan", () => api.deleteScan(1)],
  ["delete contact", () => api.deleteContactSubmission(1)],
  [
    "upload",
    () => api.scanEvidence({ strategyName: "test", file: new Blob(["test"]) }),
  ],
] as const)(
  "%s sends CSRF and cookies without bearer credentials",
  async (_, invoke) => {
    response = json(204);
    if (_ === "upload") response = json(200, {});
    await invoke();
    const options = vi.mocked(fetch).mock.calls[1][1];
    expect(options?.credentials).toBe("include");
    expect(new Headers(options?.headers).get("X-CSRF-Token")).toBe(
      "synthetic-csrf",
    );
    expect(new Headers(options?.headers).has("Authorization")).toBe(false);
  },
);
test("CSRF bootstrap failure prevents mutation", async () => {
  vi.mocked(fetch).mockResolvedValue(json(403, { detail: "no" }));
  await expect(api.login("u@example.com", "password")).rejects.toThrow(
    /verify/,
  );
  expect(fetch).toHaveBeenCalledTimes(1);
});
test("logout failures propagate and do not declare the session expired", async () => {
  const expired = vi.fn();
  window.addEventListener("autoaudit:session-expired", expired);
  response = json(401, { detail: "failed" });
  await expect(api.logout()).rejects.toThrow("failed");
  expect(expired).not.toHaveBeenCalled();
  window.removeEventListener("autoaudit:session-expired", expired);
});
test("refresh checks the shared cookie after a concurrent rotation rejection", async () => {
  const expired = vi.fn();
  window.addEventListener("autoaudit:session-expired", expired);
  vi.mocked(fetch).mockImplementation(async (url) =>
    String(url).endsWith("/auth/csrf")
      ? json(200, { csrf_token: "csrf" })
      : String(url).endsWith("/auth/refresh")
        ? json(401, { detail: "stale" })
        : json(200, { id: 1 }),
  );
  await api.refreshSession();
  expect(expired).not.toHaveBeenCalled();
  expect(
    vi
      .mocked(fetch)
      .mock.calls.some(([url]) => String(url).endsWith("/auth/users/me")),
  ).toBe(true);
  window.removeEventListener("autoaudit:session-expired", expired);
});
test("expired current cookie after failed refresh requires reauthentication", async () => {
  const expired = vi.fn();
  window.addEventListener("autoaudit:session-expired", expired);
  response = json(401, { detail: "Expired" });
  await expect(api.refreshSession()).rejects.toThrow("Expired");
  expect(expired).toHaveBeenCalledOnce();
  window.removeEventListener("autoaudit:session-expired", expired);
});
test("missing evidence fields fail before network requests", async () => {
  await expect(
    api.scanEvidence({ strategyName: "", file: new Blob() }),
  ).rejects.toThrow("Strategy");
  await expect(
    api.scanEvidence({ strategyName: "test", file: null as unknown as File }),
  ).rejects.toThrow("file");
  expect(fetch).not.toHaveBeenCalled();
});
test("non-success response preserves API status and message", async () => {
  response = json(401, { detail: "Unauthorized" });
  await expect(api.getCurrentUser()).rejects.toMatchObject({
    status: 401,
    message: "Unauthorized",
  });
});
test("network failure reports status zero", async () => {
  vi.mocked(fetch).mockRejectedValue(new Error("Network error"));
  await expect(api.getCurrentUser()).rejects.toMatchObject({ status: 0 });
});
test("204 response does not require JSON", async () => {
  response = json(204);
  expect(await api.getSettings()).toBeUndefined();
});

test("late unauthorized response from before login cannot expire the new session", async () => {
  let finishOld!: (value: Response) => void;
  let issuedOld = false;
  const expired = vi.fn();
  window.addEventListener("autoaudit:session-expired", expired);
  vi.mocked(fetch).mockImplementation(async (url) => {
    if (String(url).endsWith("/auth/users/me")) {
      if (issuedOld) return json(200, { id: 1 });
      issuedOld = true;
      return new Promise<Response>((resolve) => {
        finishOld = resolve;
      });
    }
    if (String(url).endsWith("/auth/csrf"))
      return json(200, { csrf_token: "csrf" });
    return json(204);
  });
  const old = api.getCurrentUser().catch(() => null);
  await api.login("user@example.com", "password");
  finishOld(json(401, { detail: "old request" }));
  await old;
  expect(expired).not.toHaveBeenCalled();
  window.removeEventListener("autoaudit:session-expired", expired);
});

test("a stale protected request after another tab rotates retries with the current cookie", async () => {
  const expired = vi.fn();
  window.addEventListener("autoaudit:session-expired", expired);
  let scans = 0;
  vi.mocked(fetch).mockImplementation(async (url) => {
    if (String(url).endsWith("/auth/users/me")) return json(200, { id: 1 });
    scans += 1;
    return scans === 1 ? json(401, { detail: "stale cookie" }) : json(200, []);
  });
  expect(await api.getScans()).toEqual([]);
  expect(scans).toBe(2);
  expect(expired).not.toHaveBeenCalled();
  window.removeEventListener("autoaudit:session-expired", expired);
});
test("a stale unsafe request retries once with a fresh CSRF token after session validation", async () => {
  let attempts = 0,
    csrfCalls = 0;
  vi.mocked(fetch).mockImplementation(async (url) => {
    if (String(url).endsWith("/auth/csrf"))
      return json(200, { csrf_token: `csrf-${++csrfCalls}` });
    if (String(url).endsWith("/auth/users/me")) return json(200, { id: 1 });
    return ++attempts === 1 ? json(401, { detail: "stale" }) : json(204);
  });
  await api.deleteScan(1);
  expect(attempts).toBe(2);
  expect(csrfCalls).toBe(2);
  expect(
    new Headers(vi.mocked(fetch).mock.calls.at(-1)?.[1]?.headers).get(
      "X-CSRF-Token",
    ),
  ).toBe("csrf-2");
});

test.each([
  [401, false],
  [200, false],
  [200, true],
] as const)(
  "unused probe bodies are released (probe %s, retry %s)",
  async (probeStatus, retry) => {
    const original = json(401, { detail: "stale" });
    const probe = json(
      probeStatus,
      probeStatus === 200 ? { id: 1 } : { detail: "expired" },
    );
    const originalCancel = vi.spyOn(original.body!, "cancel");
    const probeCancel = vi.spyOn(probe.body!, "cancel");
    vi.mocked(fetch)
      .mockResolvedValueOnce(original)
      .mockResolvedValueOnce(probe)
      .mockResolvedValueOnce(json(200, []));
    if (probeStatus === 401) {
      await expect(api.getCurrentUser()).rejects.toMatchObject({ status: 401 });
      expect(probeCancel).toHaveBeenCalledOnce();
      expect(originalCancel).not.toHaveBeenCalled();
      expect(original.bodyUsed).toBe(true);
    } else if (retry) {
      expect(await api.getScans()).toEqual([]);
      expect(originalCancel).toHaveBeenCalledOnce();
      expect(probeCancel).toHaveBeenCalledOnce();
    } else {
      expect(await api.getCurrentUser()).toEqual({ id: 1 });
      expect(originalCancel).toHaveBeenCalledOnce();
      expect(probeCancel).not.toHaveBeenCalled();
      expect(probe.bodyUsed).toBe(true);
    }
  },
);
test("failed CSRF bootstrap releases its unused response body", async () => {
  const denied = json(403, { detail: "denied" });
  const cancel = vi.spyOn(denied.body!, "cancel");
  vi.mocked(fetch).mockResolvedValueOnce(denied);
  await expect(api.logout()).rejects.toMatchObject({ status: 403 });
  expect(cancel).toHaveBeenCalledOnce();
});
