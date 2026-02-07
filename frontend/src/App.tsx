import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from './context/AuthContext'
import ThemeSwitcher from './components/ThemeSwitcher'
import { Badge, Button } from './components/ui'

function App() {
  const { user, logout } = useAuth()
  const [mobileNavOpen, setMobileNavOpen] = useState(false)

  const navItems = [
    { label: 'Dashboard', to: '/', end: true },
    { label: 'Scanners', to: '/scanners' },
    { label: 'Networks', to: '/networks' },
    { label: 'Scans', to: '/scans' },
    { label: 'Hosts', to: '/hosts' },
    { label: 'Risk Overview', to: '/risk-overview' },
    { label: 'Trends', to: '/trends' },
    { label: 'SSH Security', to: '/ssh-security' },
    { label: 'Policy', to: '/policy' },
    ...(user?.role === 'admin' ? [{ label: 'Users', to: '/users' }] : []),
  ]

  const navLinkClass = ({ isActive }: { isActive: boolean }) =>
    `rounded-full border px-3 py-1 transition ${
      isActive
        ? 'border-slate-900 bg-slate-900 text-white dark:border-white dark:bg-white dark:text-slate-900'
        : 'border-slate-200/70 bg-white/60 text-slate-500 hover:border-slate-300 hover:text-slate-700 dark:border-slate-800/70 dark:bg-slate-900/60 dark:text-slate-300 dark:hover:border-slate-700'
    }`

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100">
      <header className="relative z-20 border-b border-slate-200 bg-white/70 backdrop-blur dark:border-slate-800 dark:bg-slate-950/70">
        <div className="mx-auto flex max-w-[1600px] flex-col gap-4 px-6 py-5 md:flex-row md:items-center md:justify-between">
          <div className="flex flex-col gap-3">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="font-display text-xl text-slate-900 dark:text-white">
                  Open Port Monitor
                </h1>
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  Security scanning and alerting dashboard
                </p>
              </div>
              {/* Mobile hamburger */}
              <button
                type="button"
                onClick={() => setMobileNavOpen(!mobileNavOpen)}
                className="rounded-lg border border-slate-200 p-2 text-slate-600 transition hover:bg-slate-100 md:hidden dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                aria-label="Toggle navigation"
              >
                <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  {mobileNavOpen ? (
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M6 18L18 6M6 6l12 12"
                    />
                  ) : (
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M4 6h16M4 12h16M4 18h16"
                    />
                  )}
                </svg>
              </button>
            </div>
            {/* Desktop nav */}
            <nav className="hidden flex-wrap gap-2 text-xs font-semibold text-slate-500 md:flex dark:text-slate-400">
              {navItems.map((item) => (
                <NavLink key={item.to} to={item.to} end={item.end} className={navLinkClass}>
                  {item.label}
                </NavLink>
              ))}
            </nav>
          </div>
          {user ? (
            <div className="hidden flex-wrap items-center gap-3 text-sm md:flex">
              <ThemeSwitcher />
              <Badge colorClasses="border-slate-200 bg-white text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300">
                {user.role}
              </Badge>
              <div className="flex flex-col text-right">
                <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {user.email}
                </span>
                <span className="text-xs text-slate-500 dark:text-slate-400">Signed in</span>
              </div>
              <Button variant="secondary" onClick={() => void logout()}>
                Logout
              </Button>
            </div>
          ) : null}
        </div>

        {/* Mobile slide-out nav */}
        {mobileNavOpen && (
          <div className="border-t border-slate-200 bg-white/95 px-6 py-4 backdrop-blur md:hidden dark:border-slate-800 dark:bg-slate-950/95">
            <nav className="flex flex-col gap-2 text-xs font-semibold">
              {navItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  onClick={() => setMobileNavOpen(false)}
                  className={navLinkClass}
                >
                  {item.label}
                </NavLink>
              ))}
            </nav>
            {user && (
              <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-slate-200/70 pt-4 text-sm dark:border-slate-800/70">
                <ThemeSwitcher />
                <Badge colorClasses="border-slate-200 bg-white text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300">
                  {user.role}
                </Badge>
                <span className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                  {user.email}
                </span>
                <Button variant="secondary" onClick={() => void logout()}>
                  Logout
                </Button>
              </div>
            )}
          </div>
        )}
      </header>
      <main className="mx-auto max-w-[1600px] px-6 py-10">
        <Outlet />
      </main>
    </div>
  )
}

export default App
