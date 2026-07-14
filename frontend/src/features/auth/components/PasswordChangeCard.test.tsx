import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

import { useAuthStore } from "@/stores/auth.store";

const navigateMock = vi.fn();
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => navigateMock,
}));

// Import after mocks
import { PasswordChangeCard } from "./PasswordChangeCard";

describe("PasswordChangeCard", () => {
  beforeEach(() => {
    useAuthStore.setState({
      token: "test-token",
      user: null,
      isAuthenticated: true,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    navigateMock.mockReset();
  });

  function fill(current: string, next: string, confirm: string) {
    fireEvent.change(screen.getByLabelText("Current password"), {
      target: { value: current },
    });
    fireEvent.change(screen.getByLabelText("New password"), {
      target: { value: next },
    });
    fireEvent.change(screen.getByLabelText("Confirm new password"), {
      target: { value: confirm },
    });
  }

  it("shows a mismatch error and keeps submit disabled", () => {
    render(<PasswordChangeCard />);
    fill("old-pass", "new-password-1", "different");
    expect(screen.getByText("Passwords do not match.")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Change password" }),
    ).toBeDisabled();
  });

  it("rejects short new passwords", () => {
    render(<PasswordChangeCard />);
    fill("old-pass", "short", "short");
    expect(screen.getByText("At least 8 characters.")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Change password" }),
    ).toBeDisabled();
  });

  it("posts to the change-password endpoint and signs out", async () => {
    const mockFetch = vi.fn().mockResolvedValue({ ok: true, status: 204 });
    vi.stubGlobal("fetch", mockFetch);

    render(<PasswordChangeCard />);
    fill("old-pass", "new-password-1", "new-password-1");
    fireEvent.click(screen.getByRole("button", { name: "Change password" }));

    await waitFor(() => expect(mockFetch).toHaveBeenCalled());
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe("/api/auth/change-password");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({
      current_password: "old-pass",
      new_password: "new-password-1",
    });

    await waitFor(() =>
      expect(useAuthStore.getState().isAuthenticated).toBe(false),
    );
    expect(navigateMock).toHaveBeenCalledWith({ to: "/login" });
  });
});
