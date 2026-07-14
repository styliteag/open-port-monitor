import { Link, useRouterState } from "@tanstack/react-router";
import {
  Bell,
  Building,
  ChevronLeft,
  ChevronRight,
  FileCode,
  Gauge,
  LayoutDashboard,
  Monitor,
  Network,
  Radar,
  Server,
  Settings2,
  ShieldAlert,
  Users,
  Zap,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { hasRole } from "@/lib/roles";
import { NAV_AREAS } from "@/lib/terminology";
import { cn } from "@/lib/utils";
import type { UserRole } from "@/stores/auth.store";
import { useAuthStore } from "@/stores/auth.store";
import { useUiStore } from "@/stores/ui.store";

interface NavItem {
  label: string;
  href: string;
  icon: React.ComponentType<{ className?: string }>;
}

interface NavArea {
  label?: string;
  minRole?: UserRole;
  items: NavItem[];
}

const NAV_AREAS_CONFIG: NavArea[] = [
  {
    items: [{ label: "Overview", href: "/overview", icon: Gauge }],
  },
  {
    label: NAV_AREAS.monitor,
    items: [
      { label: "Dashboard", href: "/", icon: LayoutDashboard },
      { label: "Alerts", href: "/alerts", icon: ShieldAlert },
      { label: "Hosts", href: "/hosts", icon: Monitor },
      { label: "Scans", href: "/scans", icon: Radar },
    ],
  },
  {
    label: NAV_AREAS.configuration,
    minRole: "operator",
    items: [
      { label: "Networks", href: "/networks", icon: Network },
      { label: "Scanners", href: "/scanners", icon: Server },
      { label: "Scan Templates", href: "/scan-templates", icon: FileCode },
      { label: "Alerting", href: "/alerting", icon: Bell },
    ],
  },
  {
    label: NAV_AREAS.administration,
    minRole: "admin",
    items: [
      { label: "Users & Roles", href: "/admin/users", icon: Users },
      { label: "Organization", href: "/admin/organization", icon: Building },
      { label: "System", href: "/admin/system", icon: Settings2 },
    ],
  },
];

function NavGroup({ area, collapsed }: { area: NavArea; collapsed: boolean }) {
  const routerState = useRouterState();
  const currentPath = routerState.location.pathname;

  return (
    <div className="space-y-1">
      {area.label && !collapsed && (
        <p className="px-3 py-1 text-xs font-emphasis uppercase tracking-wider text-muted-foreground">
          {area.label}
        </p>
      )}
      {area.items.map((item) => {
        const isActive =
          item.href === "/"
            ? currentPath === "/"
            : currentPath.startsWith(item.href);

        return (
          <Link
            key={item.href}
            to={item.href}
            className={cn(
              "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
              isActive
                ? "bg-accent text-accent-foreground font-emphasis"
                : "text-muted-foreground hover:text-foreground hover:bg-accent",
              collapsed && "justify-center px-2",
            )}
            title={collapsed ? item.label : undefined}
          >
            <item.icon className="h-4 w-4 shrink-0" />
            {!collapsed && <span>{item.label}</span>}
          </Link>
        );
      })}
    </div>
  );
}

export function Sidebar() {
  const collapsed = useUiStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const openQuickScan = useUiStore((s) => s.openQuickScan);
  const userRole = useAuthStore((s) => s.user?.role);

  const visibleAreas = NAV_AREAS_CONFIG.filter(
    (area) => !area.minRole || hasRole(userRole, area.minRole),
  );

  return (
    <aside
      className={cn(
        "flex h-screen flex-col border-r border-border bg-background transition-all duration-200",
        collapsed ? "w-16" : "w-56",
      )}
    >
      {/* Logo */}
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        <ShieldAlert className="h-6 w-6 text-primary shrink-0" />
        {!collapsed && (
          <span className="text-sm font-strong tracking-tight text-foreground">
            STYLiTE Orbit Monitor
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 space-y-4 overflow-y-auto p-3 scrollbar-none">
        {visibleAreas.map((area) => (
          <NavGroup key={area.label ?? "top"} area={area} collapsed={collapsed} />
        ))}
      </nav>

      {/* Scan Now Button */}
      <div className="border-t border-border p-3">
        <Button onClick={openQuickScan} className="w-full" title="Quick Scan">
          <Zap className="h-4 w-4" />
          {!collapsed && <span>Scan Now</span>}
        </Button>
      </div>

      {/* Collapse Toggle */}
      <div className="border-t border-border p-3">
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleSidebar}
          className="w-full"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? (
            <ChevronRight className="h-4 w-4" />
          ) : (
            <ChevronLeft className="h-4 w-4" />
          )}
        </Button>
      </div>
    </aside>
  );
}
