import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { vi, beforeEach, afterEach, test, expect } from "vitest";
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
  vi.mocked(api.getCurrentUser).mockResolvedValue({ id: 1 });
});
afterEach(cleanup);
test("requires its provider", () => {
  expect(() => renderHook(useAuth)).toThrow(/AuthProvider/);
});
test("does not trust cached users and removes legacy credentials", async () => {
  localStorage.setItem("token", "legacy-token");
  sessionStorage.setItem("token", "legacy-session");
  localStorage.setItem("user", '{"id":1}');
  sessionStorage.setItem(
    "autoaudit.oauth.google.callback.params",
    '{"access_token":"legacy"}',
  );
  vi.mocked(api.getCurrentUser).mockRejectedValue(
    new api.APIError("Expired", 401),
  );
  const { result } = renderHook(useAuth, { wrapper: AuthProvider });
  expect(result.current.isAuthenticated).toBe(false);
  await waitFor(() => expect(result.current.isLoading).toBe(false));
  expect(result.current.user).toBe(null);
  expect(localStorage.getItem("token")).toBe(null);
  expect(sessionStorage.getItem("token")).toBe(null);
  expect(sessionStorage.getItem("autoaudit.oauth.google.callback.params")).toBe(
    null,
  );
});
test("login confirms the cookie session without persisting credentials", async () => {
  const { result } = renderHook(useAuth, { wrapper: AuthProvider });
  await waitFor(() => expect(result.current.isLoading).toBe(false));
  vi.mocked(api.login).mockResolvedValue(undefined);
  await act(async () => {
    await result.current.login("user@example.com", "password", true);
  });
  expect(api.login).toHaveBeenCalledWith("user@example.com", "password");
  expect(api.getCurrentUser).toHaveBeenLastCalledWith();
  expect(result.current.isAuthenticated).toBe(true);
  expect(localStorage.getItem("token")).toBe(null);
  expect(sessionStorage.getItem("token")).toBe(null);
});
test("OAuth completion validates existing cookie rather than accepting URL credentials", async () => {
  const { result } = renderHook(useAuth, { wrapper: AuthProvider });
  await waitFor(() => expect(result.current.isLoading).toBe(false));
  await act(async () => {
    await result.current.completeOAuthLogin();
  });
  expect(api.getCurrentUser).toHaveBeenLastCalledWith();
  expect(result.current.isAuthenticated).toBe(true);
});
test("successful logout waits for server revocation before changing user state", async () => {
  let finish!: () => void;
  vi.mocked(api.logout).mockReturnValue(
    new Promise<void>((resolve) => {
      finish = resolve;
    }),
  );
  const { result } = renderHook(useAuth, { wrapper: AuthProvider });
  await waitFor(() => expect(result.current.isAuthenticated).toBe(true));
  let pending!: Promise<void>;
  act(() => {
    pending = result.current.logout();
  });
  expect(result.current.isAuthenticated).toBe(true);
  await act(async () => {
    finish();
    await pending;
  });
  expect(result.current.isAuthenticated).toBe(false);
});
test("protected API expiry requires reauthentication", async () => {
  const { result } = renderHook(useAuth, { wrapper: AuthProvider });
  await waitFor(() => expect(result.current.isAuthenticated).toBe(true));
  act(() => {
    window.dispatchEvent(new Event("autoaudit:session-expired"));
  });
  expect(result.current.isAuthenticated).toBe(false);
});
