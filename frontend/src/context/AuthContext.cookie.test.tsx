import { act, renderHook, waitFor } from "@testing-library/react";
import { vi, beforeEach, test, expect } from "vitest";
import { AuthProvider, useAuth } from "./AuthContext";
import * as api from "../api/client";
vi.mock("../api/client", async () => ({
  ...(await vi.importActual("../api/client")),
  getCurrentUser: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
  refreshSession: vi.fn(),
}));
beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  sessionStorage.clear();
});
test("validates a cookie session without a browser token", async () => {
  vi.mocked(api.getCurrentUser).mockResolvedValue({
    id: 1,
    email: "user@example.test",
  });
  const { result } = renderHook(useAuth, { wrapper: AuthProvider });
  await waitFor(() => expect(result.current.isLoading).toBe(false));
  expect(api.getCurrentUser).toHaveBeenCalledWith();
  expect(result.current.isAuthenticated).toBe(true);
  expect("token" in result.current).toBe(false);
});
test("logout failure retains the authenticated state and propagates an actionable error", async () => {
  vi.mocked(api.getCurrentUser).mockResolvedValue({ id: 1 });
  vi.mocked(api.logout).mockRejectedValue(new Error("Network unavailable"));
  const { result } = renderHook(useAuth, { wrapper: AuthProvider });
  await waitFor(() => expect(result.current.isAuthenticated).toBe(true));
  await act(async () => {
    await expect(result.current.logout()).rejects.toThrow(
      "Network unavailable",
    );
  });
  expect(result.current.isAuthenticated).toBe(true);
});

test("a late startup failure cannot clear a newer successful login", async () => {
  let failStartup!: (error: Error) => void;
  vi.mocked(api.getCurrentUser)
    .mockReturnValueOnce(
      new Promise((_resolve, reject) => {
        failStartup = reject;
      }),
    )
    .mockResolvedValue({ id: 1 });
  vi.mocked(api.login).mockResolvedValue(undefined);
  const { result } = renderHook(useAuth, { wrapper: AuthProvider });
  await act(async () => {
    await result.current.login("user@example.com", "password");
  });
  await act(async () => {
    failStartup(new Error("stale request"));
  });
  expect(result.current.isAuthenticated).toBe(true);
});

test("idle tabs do not refresh; recent visible activity permits renewal", async () => {
  vi.mocked(api.getCurrentUser).mockResolvedValue({ id: 1 });
  vi.mocked(api.refreshSession).mockResolvedValue(undefined);
  vi.useFakeTimers();
  try {
    const { result, unmount } = renderHook(useAuth, { wrapper: AuthProvider });
    await act(async () => {
      await Promise.resolve();
    });
    expect(result.current.isAuthenticated).toBe(true);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5 * 60 * 1000);
    });
    expect(api.refreshSession).not.toHaveBeenCalled();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4 * 60 * 1000);
      window.dispatchEvent(new Event("keydown"));
      await vi.advanceTimersByTimeAsync(60 * 1000);
    });
    expect(api.refreshSession).toHaveBeenCalledOnce();
    unmount();
  } finally {
    vi.useRealTimers();
  }
});
