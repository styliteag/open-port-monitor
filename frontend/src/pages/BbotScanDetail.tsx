import { useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { api } from '../lib/api'

interface BbotFinding {
  id: number
  bbot_scan_id: number
  timestamp: string
  event_type: string
  data: string
  host: string | null
  port: number | null
  protocol: string | null
  module: string | null
  severity: string | null
  tags: string[] | null
  raw_event: Record<string, unknown> | null
}

interface BbotScanDetail {
  id: number
  network_id: number
  scanner_id: number | null
  status: string
  started_at: string | null
  completed_at: string | null
  cancelled_at: string | null
  cancelled_by: number | null
  cancelled_by_email: string | null
  error_message: string | null
  target: string
  modules: string | null
  findings: BbotFinding[]
}

export default function BbotScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()

  const { data: scan, isLoading } = useQuery<BbotScanDetail>({
    queryKey: ['bbot-scan', scanId],
    queryFn: async () => api.get(`/api/bbot/scans/${scanId}`),
    enabled: !!scanId,
  })

  const formatDate = (dateStr: string | null) => {
    if (!dateStr) return 'N/A'
    return new Date(dateStr).toLocaleString()
  }

  const getStatusBadge = (status: string) => {
    const colors: Record<string, string> = {
      planned: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      running: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
      completed: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      failed: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
      cancelled: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200',
    }
    return (
      <span
        className={`rounded-full px-3 py-1 text-xs font-semibold ${colors[status] || 'bg-gray-100 text-gray-800'}`}
      >
        {status}
      </span>
    )
  }

  const getSeverityBadge = (severity: string | null) => {
    if (!severity) return null
    const colors: Record<string, string> = {
      critical: 'bg-red-600 text-white',
      high: 'bg-orange-600 text-white',
      medium: 'bg-yellow-600 text-white',
      low: 'bg-blue-600 text-white',
      info: 'bg-gray-600 text-white',
    }
    return (
      <span
        className={`rounded-full px-2 py-0.5 text-xs font-semibold ${colors[severity.toLowerCase()] || 'bg-gray-600 text-white'}`}
      >
        {severity}
      </span>
    )
  }

  if (isLoading) {
    return <div className="text-center text-slate-500">Loading...</div>
  }

  if (!scan) {
    return <div className="text-center text-slate-500">Scan not found</div>
  }

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/bbot-scans"
          className="mb-4 inline-block text-sm text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
        >
          ← Back to Scans
        </Link>
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white">
          Bbot Scan #{scan.id}
        </h1>
        <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
          Target: {scan.target}
        </p>
      </div>

      {/* Scan info card */}
      <div className="rounded-lg border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900">
        <h2 className="mb-4 text-lg font-semibold text-slate-900 dark:text-white">
          Scan Information
        </h2>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div>
            <div className="text-sm font-medium text-slate-500 dark:text-slate-400">Status</div>
            <div className="mt-1">{getStatusBadge(scan.status)}</div>
          </div>
          <div>
            <div className="text-sm font-medium text-slate-500 dark:text-slate-400">
              Modules
            </div>
            <div className="mt-1 text-sm text-slate-900 dark:text-slate-100">
              {scan.modules || 'Default modules'}
            </div>
          </div>
          <div>
            <div className="text-sm font-medium text-slate-500 dark:text-slate-400">Started</div>
            <div className="mt-1 text-sm text-slate-900 dark:text-slate-100">
              {formatDate(scan.started_at)}
            </div>
          </div>
          <div>
            <div className="text-sm font-medium text-slate-500 dark:text-slate-400">
              Completed
            </div>
            <div className="mt-1 text-sm text-slate-900 dark:text-slate-100">
              {formatDate(scan.completed_at)}
            </div>
          </div>
          {scan.error_message && (
            <div className="col-span-2">
              <div className="text-sm font-medium text-red-600 dark:text-red-400">Error</div>
              <div className="mt-1 text-sm text-red-600 dark:text-red-400">
                {scan.error_message}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Findings */}
      <div className="rounded-lg border border-slate-200 bg-white p-6 dark:border-slate-800 dark:bg-slate-900">
        <h2 className="mb-4 text-lg font-semibold text-slate-900 dark:text-white">
          Findings ({scan.findings.length})
        </h2>
        {scan.findings.length === 0 ? (
          <div className="text-center text-slate-500 dark:text-slate-400">No findings yet</div>
        ) : (
          <div className="space-y-3">
            {scan.findings.map((finding) => (
              <div
                key={finding.id}
                className="rounded-lg border border-slate-200 bg-slate-50 p-4 dark:border-slate-700 dark:bg-slate-800"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-blue-100 px-2 py-1 text-xs font-mono text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                        {finding.event_type}
                      </span>
                      {finding.severity && getSeverityBadge(finding.severity)}
                      {finding.module && (
                        <span className="text-xs text-slate-500 dark:text-slate-400">
                          via {finding.module}
                        </span>
                      )}
                    </div>
                    <div className="mt-2 font-mono text-sm text-slate-900 dark:text-slate-100">
                      {finding.data}
                    </div>
                    <div className="mt-2 flex gap-4 text-xs text-slate-500 dark:text-slate-400">
                      {finding.host && (
                        <div>
                          <span className="font-medium">Host:</span> {finding.host}
                        </div>
                      )}
                      {finding.port && (
                        <div>
                          <span className="font-medium">Port:</span> {finding.port}
                          {finding.protocol && `/${finding.protocol}`}
                        </div>
                      )}
                      <div>
                        <span className="font-medium">Time:</span> {formatDate(finding.timestamp)}
                      </div>
                    </div>
                    {finding.tags && finding.tags.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {finding.tags.map((tag, idx) => (
                          <span
                            key={idx}
                            className="rounded bg-slate-200 px-2 py-0.5 text-xs text-slate-700 dark:bg-slate-700 dark:text-slate-300"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
