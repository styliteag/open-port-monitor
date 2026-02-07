import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { fetchJson, API_BASE_URL } from '../lib/api'
import { Card, Badge, EmptyState } from '../components/ui'
import { ALERT_TYPE_LABELS_COMPACT, ALERT_TYPE_STYLES_COMPACT } from '../constants/alerts'
import type {
  AlertListResponse,
  LatestScansByNetworkResponse,
  NetworkListResponse,
  ScannerListResponse,
} from '../types'

const formatDateTime = (value: Date) =>
  new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(value)

const parseUtcDate = (dateStr: string) =>
  new Date(dateStr.endsWith('Z') ? dateStr : dateStr + 'Z')

const formatRelativeTime = (value: Date, now: Date) => {
  const diffMs = now.getTime() - value.getTime()
  if (diffMs < 0) return 'Just now'
  const minutes = Math.floor(diffMs / 60000)
  if (minutes < 1) return 'Just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

const Home = () => {
  const { token } = useAuth()
  const now = new Date()

  const backendVersionQuery = useQuery({
    queryKey: ['version', 'backend'],
    queryFn: async () => {
      const response = await fetch(`${API_BASE_URL}/api/version`)
      if (!response.ok) throw new Error('Failed to fetch backend version')
      const data: { version: string; component: string } = await response.json()
      return data.version
    },
    retry: 1,
    staleTime: 5 * 60 * 1000,
  })

  const frontendVersion = import.meta.env.VITE_APP_VERSION || 'unknown'
  const backendVersion = backendVersionQuery.data ?? 'unknown'

  const networksQuery = useQuery({
    queryKey: ['networks'],
    queryFn: () => fetchJson<NetworkListResponse>('/api/networks', token ?? ''),
    enabled: Boolean(token),
  })
  const scannersQuery = useQuery({
    queryKey: ['scanners'],
    queryFn: () => fetchJson<ScannerListResponse>('/api/scanners', token ?? ''),
    enabled: Boolean(token),
  })
  const recentAlertsQuery = useQuery({
    queryKey: ['alerts', 'recent'],
    queryFn: () => fetchJson<AlertListResponse>('/api/alerts?limit=10', token ?? ''),
    enabled: Boolean(token),
  })
  const activeAlertsQuery = useQuery({
    queryKey: ['alerts', 'active-count'],
    queryFn: () => fetchJson<AlertListResponse>('/api/alerts?acknowledged=false&limit=200', token ?? ''),
    enabled: Boolean(token),
  })
  const latestScansQuery = useQuery({
    queryKey: ['scans', 'latest-by-network'],
    queryFn: () => fetchJson<LatestScansByNetworkResponse>('/api/scans/latest-by-network', token ?? ''),
    enabled: Boolean(token),
  })

  const latestScanDate = useMemo(() => {
    const latestScans = latestScansQuery.data?.latest_scans ?? []
    let latest: Date | null = null
    for (const { scan } of latestScans) {
      if (!scan) continue
      const candidate = parseUtcDate(scan.completed_at ?? scan.started_at ?? '')
      if (Number.isNaN(candidate.getTime())) continue
      if (!latest || candidate > latest) latest = candidate
    }
    return latest
  }, [latestScansQuery.data])

  const totalNetworks = networksQuery.data?.networks.length ?? 0
  const totalScanners = scannersQuery.data?.scanners.length ?? 0
  const activeAlertsCount = activeAlertsQuery.data?.alerts.length ?? 0
  const activeAlertsLabel = activeAlertsCount === 200 ? '200+' : `${activeAlertsCount}`
  const recentAlerts = recentAlertsQuery.data?.alerts ?? []
  const scanners = scannersQuery.data?.scanners ?? []
  const latestScanLabel = latestScanDate ? formatRelativeTime(latestScanDate, now) : 'No scans yet'
  const latestScanDetail = latestScanDate ? formatDateTime(latestScanDate) : 'Awaiting the first scan'

  const isLoading = networksQuery.isLoading || scannersQuery.isLoading || recentAlertsQuery.isLoading || activeAlertsQuery.isLoading || latestScansQuery.isLoading
  const hasError = networksQuery.isError || scannersQuery.isError || recentAlertsQuery.isError || activeAlertsQuery.isError || latestScansQuery.isError
  const showPlaceholder = isLoading || hasError

  const summaryCards = [
    { label: 'Networks', value: `${totalNetworks}`, detail: 'Total monitored ranges', accent: 'text-cyan-600 dark:text-cyan-200' },
    { label: 'Scanners', value: `${totalScanners}`, detail: 'Scanner locations', accent: 'text-emerald-600 dark:text-emerald-200' },
    { label: 'Active alerts', value: activeAlertsLabel, detail: 'Unacknowledged alerts', accent: 'text-amber-600 dark:text-amber-200' },
    { label: 'Last scan', value: latestScanLabel, detail: latestScanDetail, accent: 'text-sky-600 dark:text-sky-200' },
  ]

  const quickLinks = [
    { title: 'Networks', description: 'Review monitored ranges and schedules.', to: '/networks' },
    { title: 'Scans', description: 'Track scan history and diffs.', to: '/scans' },
    { title: 'Alerts', description: 'Investigate and acknowledge issues.', to: '/risk-overview' },
    { title: 'Open Ports', description: 'Inspect current exposed services.', to: '/ports' },
    { title: 'Policy', description: 'Manage security governance rules.', to: '/policy' },
  ]

  return (
    <div className="relative">
      {/* Decorative blurs */}
      <div className="pointer-events-none absolute -left-24 top-12 h-72 w-72 animate-drift rounded-full bg-cyan-500/20 blur-[120px]" />
      <div className="pointer-events-none absolute right-0 top-40 h-72 w-72 animate-drift rounded-full bg-emerald-500/20 blur-[140px]" />
      <div className="pointer-events-none absolute -bottom-32 left-1/3 h-72 w-72 animate-drift rounded-full bg-sky-500/10 blur-[160px]" />

      <section className="relative z-10 space-y-8">
        {/* Hero card */}
        <Card variant="glass" padding="lg" className="animate-rise">
          <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
            <div>
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400">Dashboard overview</p>
              <h2 className="mt-3 font-display text-3xl text-slate-900 dark:text-white">Network security at a glance</h2>
              <p className="mt-2 max-w-2xl text-sm text-slate-600 dark:text-slate-300">
                Monitor coverage, scanner health, and the latest alerts in one glance.
              </p>
            </div>
            <div className="flex flex-col items-end gap-2">
              <Card variant="flush" padding="sm" className="text-xs text-slate-500 shadow-sm dark:text-slate-300">
                {isLoading ? 'Syncing latest telemetry...' : `Updated ${formatDateTime(now)}`}
              </Card>
              <div className="rounded-2xl border border-slate-200/50 bg-slate-100/60 px-3 py-1.5 text-xs font-medium text-slate-600 dark:border-slate-700/50 dark:bg-slate-800/40 dark:text-slate-400">
                Frontend v{frontendVersion} | Backend v{backendVersion}
              </div>
            </div>
          </div>

          {/* Summary cards */}
          <div className="mt-8 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {summaryCards.map((card, i) => (
              <Card key={card.label} hover style={{ animationDelay: `${i * 0.08}s` }} className="animate-rise">
                <p className="text-xs text-slate-500 dark:text-slate-400">{card.label}</p>
                <span className={`mt-3 block text-2xl font-semibold ${card.accent}`}>
                  {showPlaceholder ? '—' : card.value}
                </span>
                <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{card.detail}</p>
              </Card>
            ))}
          </div>

          {/* Quick links */}
          <div className="mt-8 grid gap-4 md:grid-cols-2">
            {quickLinks.map((link, i) => (
              <Link
                key={link.title}
                to={link.to}
                style={{ animationDelay: `${0.2 + i * 0.08}s` }}
                className="group animate-rise rounded-2xl border border-slate-200/70 bg-white/70 p-5 text-left shadow-sm transition duration-300 hover:-translate-y-1 hover:border-slate-300 hover:bg-white dark:border-slate-800/70 dark:bg-slate-950/60 dark:hover:border-slate-700"
              >
                <h3 className="font-display text-lg text-slate-900 dark:text-white">{link.title}</h3>
                <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{link.description}</p>
                <span className="mt-3 inline-flex items-center text-xs font-semibold text-cyan-600 dark:text-cyan-300">Explore</span>
              </Link>
            ))}
          </div>
        </Card>

        {/* Bottom grid: Alerts + Scanners */}
        <div className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
          <Card variant="glass" padding="lg">
            <div className="flex items-center justify-between">
              <h3 className="font-display text-xl text-slate-900 dark:text-white">Recent alerts</h3>
              <Link to="/risk-overview" className="text-xs font-semibold text-cyan-600 dark:text-cyan-300">View all</Link>
            </div>
            <div className="mt-4 space-y-3">
              {hasError ? (
                <EmptyState message="Unable to load alerts right now." variant="error" />
              ) : recentAlerts.length === 0 ? (
                <EmptyState message="No alerts detected in the latest scans." />
              ) : (
                recentAlerts.map((alert) => (
                  <Card key={alert.id} padding="sm" className="flex flex-col gap-3">
                    <div className="flex flex-wrap items-center gap-3">
                      <span className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold tracking-wide ${ALERT_TYPE_STYLES_COMPACT[alert.type]}`}>
                        {ALERT_TYPE_LABELS_COMPACT[alert.type]}
                      </span>
                      <span className="text-sm font-semibold text-slate-900 dark:text-white">{alert.network_name ?? 'Global'}</span>
                      <span className="text-xs text-slate-500 dark:text-slate-400">{alert.ip}:{alert.port}</span>
                    </div>
                    <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-slate-500 dark:text-slate-400">
                      <span>{alert.message}</span>
                      <span>{formatRelativeTime(parseUtcDate(alert.created_at), now)}</span>
                    </div>
                  </Card>
                ))
              )}
            </div>
          </Card>

          <Card variant="glass" padding="lg">
            <div className="flex items-center justify-between">
              <h3 className="font-display text-xl text-slate-900 dark:text-white">Scanners</h3>
              <Link to="/scanners" className="text-xs font-semibold text-cyan-600 dark:text-cyan-300">Manage</Link>
            </div>
            <div className="mt-4 space-y-3">
              {scanners.length === 0 ? (
                <EmptyState message="No scanners registered yet." />
              ) : (
                scanners.map((scanner) => {
                  const lastSeen = scanner.last_seen_at ? parseUtcDate(scanner.last_seen_at) : null
                  const isOnline = lastSeen !== null && now.getTime() - lastSeen.getTime() <= 5 * 60 * 1000
                  return (
                    <Card key={scanner.id} padding="sm" className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-semibold text-slate-900 dark:text-white">{scanner.name}</p>
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          {lastSeen ? `Last seen ${formatRelativeTime(lastSeen, now)}` : 'Awaiting first check-in'}
                        </p>
                      </div>
                      <Badge variant={isOnline ? 'success' : 'muted'}>{isOnline ? 'Online' : 'Offline'}</Badge>
                    </Card>
                  )
                })
              )}
            </div>
          </Card>
        </div>
      </section>
    </div>
  )
}

export default Home
