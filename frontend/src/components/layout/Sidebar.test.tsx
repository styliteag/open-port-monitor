import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";

import { useUiStore } from "@/stores/ui.store";
import type { UserRole } from "@/stores/auth.store";
import { useAuthStore } from "@/stores/auth.store";

// Mock TanStack Router
vi.mock("@tanstack/react-router", () => ({
  Link: ({
    children,
    to,
    ...props
  }: {
    children: React.ReactNode;
    to: string;
    className?: string;
    title?: string;
  }) => (
    <a href={to} {...props}>
      {children}
    </a>
  ),
  useRouterState: () => ({
    location: { pathname: "/" },
  }),
}));

// Import after mocks
import { Sidebar } from "./Sidebar";

function setRole(role: UserRole) {
  useAuthStore.setState({
    user: {
      id: 1,
      email: `${role}@test.com`,
      role,
      theme_preference: "dark",
    },
    token: "token",
    isAuthenticated: true,
  });
}

describe("Sidebar", () => {
  beforeEach(() => {
    useUiStore.setState({ sidebarCollapsed: false, quickScanModalOpen: false });
    setRole("admin");
  });

  it("renders the app name", () => {
    render(<Sidebar />);
    expect(screen.getByText("STYLiTE Orbit Monitor")).toBeInTheDocument();
  });

  it("renders Overview and Monitor items for every role", () => {
    setRole("viewer");
    render(<Sidebar />);
    expect(screen.getByText("Overview")).toBeInTheDocument();
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
    expect(screen.getByText("Alerts")).toBeInTheDocument();
    expect(screen.getByText("Hosts")).toBeInTheDocument();
    expect(screen.getByText("Scans")).toBeInTheDocument();
  });

  it("renders the three area labels for admins", () => {
    render(<Sidebar />);
    expect(screen.getByText("Monitor")).toBeInTheDocument();
    expect(screen.getByText("Configuration")).toBeInTheDocument();
    expect(screen.getByText("Administration")).toBeInTheDocument();
  });

  it("hides Configuration from analysts", () => {
    setRole("analyst");
    render(<Sidebar />);
    expect(screen.queryByText("Configuration")).not.toBeInTheDocument();
    expect(screen.queryByText("Networks")).not.toBeInTheDocument();
    expect(screen.queryByText("Scan Templates")).not.toBeInTheDocument();
  });

  it("shows Configuration to operators but hides Administration", () => {
    setRole("operator");
    render(<Sidebar />);
    expect(screen.getByText("Networks")).toBeInTheDocument();
    expect(screen.getByText("Scanners")).toBeInTheDocument();
    expect(screen.getByText("Scan Templates")).toBeInTheDocument();
    expect(screen.getByText("Alerting")).toBeInTheDocument();
    expect(screen.queryByText("Administration")).not.toBeInTheDocument();
    expect(screen.queryByText("Users & Roles")).not.toBeInTheDocument();
  });

  it("shows Administration items to admins", () => {
    render(<Sidebar />);
    expect(screen.getByText("Users & Roles")).toBeInTheDocument();
    expect(screen.getByText("Organization")).toBeInTheDocument();
    expect(screen.getByText("System")).toBeInTheDocument();
  });

  it("renders Scan Now button", () => {
    render(<Sidebar />);
    expect(screen.getByText("Scan Now")).toBeInTheDocument();
  });

  it("opens quick scan modal when Scan Now is clicked", () => {
    render(<Sidebar />);
    fireEvent.click(screen.getByText("Scan Now"));
    expect(useUiStore.getState().quickScanModalOpen).toBe(true);
  });

  it("hides labels when collapsed", () => {
    useUiStore.setState({ sidebarCollapsed: true, quickScanModalOpen: false });
    render(<Sidebar />);
    expect(screen.queryByText("STYLiTE Orbit Monitor")).not.toBeInTheDocument();
    expect(screen.queryByText("Dashboard")).not.toBeInTheDocument();
  });

  it("does not render retired v2 nav items", () => {
    render(<Sidebar />);
    expect(screen.queryByText("NSE Scripts")).not.toBeInTheDocument();
    expect(screen.queryByText("Trends")).not.toBeInTheDocument();
    expect(screen.queryByText("GVM Library")).not.toBeInTheDocument();
  });
});
