import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../lib/api'

interface BbotScan {
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
  findings_count: number | null
}

interface Network {
  id: number
  name: string
  cidr: string
}

export default function BbotScans() {
  const [selectedNetworkId, setSelectedNetworkId] = useState<number | null>(null)
  const [showTriggerModal, setShowTriggerModal] = useState(false)
  const [triggerForm, setTriggerForm] = useState({
    network_id: 0,
    target: '',
    modules: '',
  })

  // Fetch networks for the dropdown
  const { data: networksData } = useQuery<{ networks: Network[] }>({
    queryKey: ['networks'],
    queryFn: async () => api.get('/api/networks'),
  })

  // Fetch bbot scans
  const {
    data: scansData,
    isLoading,
    refetch: refetchScans,
  } = useQuery<{ scans: BbotScan[]; total: number }>({
    queryKey: ['bbot-scans', selectedNetworkId],
    queryFn: async () => {
      const params = selectedNetworkId ? `?network_id=${selectedNetworkId}` : ''
      return api.get(`/api/bbot/scans${params}`)
    },
  })

  const handleTriggerScan = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      await api.post('/api/bbot/scans', triggerForm)
      setShowTriggerModal(false)
      setTriggerForm({ network_id: 0, target: '', modules: '' })
      refetchScans()
    } catch (error) {
      console.error('Failed to trigger bbot scan:', error)
      alert('Failed to trigger scan')
    }
  }

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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 dark:text-white">
            Security Scans (bbot)
          </h1>
          <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
            OSINT and security scanning with bbot
          </p>
        </div>
        <button
          type="button"
          onClick={() => setShowTriggerModal(true)}
          className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700"
        >
          Trigger Scan
        </button>
      </div>

      {/* Filter */}
      <div className="flex gap-4">
        <select
          value={selectedNetworkId || ''}
          onChange={(e) => setSelectedNetworkId(e.target.value ? Number(e.target.value) : null)}
          className="rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm dark:border-slate-700 dark:bg-slate-900"
        >
          <option value="">All Networks</option>
          {networksData?.networks.map((network) => (
            <option key={network.id} value={network.id}>
              {network.name} ({network.cidr})
            </option>
          ))}
        </select>
      </div>

      {/* Scans table */}
      {isLoading ? (
        <div className="text-center text-slate-500">Loading...</div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
          <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-800">
            <thead className="bg-slate-50 dark:bg-slate-800">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  ID
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Target
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Findings
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Started
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Completed
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {scansData?.scans.map((scan) => (
                <tr
                  key={scan.id}
                  className="hover:bg-slate-50 dark:hover:bg-slate-800"
                >
                  <td className="whitespace-nowrap px-6 py-4 text-sm text-slate-900 dark:text-slate-100">
                    {scan.id}
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-900 dark:text-slate-100">
                    <div className="font-medium">{scan.target}</div>
                    {scan.modules && (
                      <div className="text-xs text-slate-500 dark:text-slate-400">
                        Modules: {scan.modules}
                      </div>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 text-sm">
                    {getStatusBadge(scan.status)}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 text-sm text-slate-900 dark:text-slate-100">
                    {scan.findings_count ?? 0}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 text-sm text-slate-500 dark:text-slate-400">
                    {formatDate(scan.started_at)}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 text-sm text-slate-500 dark:text-slate-400">
                    {formatDate(scan.completed_at)}
                  </td>
                  <td className="whitespace-nowrap px-6 py-4 text-sm">
                    <Link
                      to={`/bbot-scans/${scan.id}`}
                      className="text-blue-600 hover:text-blue-900 dark:text-blue-400 dark:hover:text-blue-300"
                    >
                      View Details
                    </Link>
                  </td>
                </tr>
              ))}
              {scansData?.scans.length === 0 && (
                <tr>
                  <td
                    colSpan={7}
                    className="px-6 py-8 text-center text-slate-500 dark:text-slate-400"
                  >
                    No bbot scans found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Trigger Modal */}
      {showTriggerModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="w-full max-w-md rounded-lg bg-white p-6 dark:bg-slate-900">
            <h2 className="mb-4 text-xl font-bold text-slate-900 dark:text-white">
              Trigger Bbot Scan
            </h2>
            <form onSubmit={handleTriggerScan} className="space-y-4">
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300">
                  Network
                </label>
                <select
                  required
                  value={triggerForm.network_id}
                  onChange={(e) =>
                    setTriggerForm({ ...triggerForm, network_id: Number(e.target.value) })
                  }
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 dark:border-slate-700 dark:bg-slate-800"
                >
                  <option value={0}>Select a network</option>
                  {networksData?.networks.map((network) => (
                    <option key={network.id} value={network.id}>
                      {network.name} ({network.cidr})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300">
                  Target (domain or IP)
                </label>
                <input
                  type="text"
                  required
                  value={triggerForm.target}
                  onChange={(e) => setTriggerForm({ ...triggerForm, target: e.target.value })}
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 dark:border-slate-700 dark:bg-slate-800"
                  placeholder="example.com or 192.168.1.1"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300">
                  Modules (optional, comma-separated)
                </label>
                <input
                  type="text"
                  value={triggerForm.modules}
                  onChange={(e) => setTriggerForm({ ...triggerForm, modules: e.target.value })}
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 dark:border-slate-700 dark:bg-slate-800"
                  placeholder="subdomain_enum,port_scan"
                />
              </div>
              <div className="flex gap-2">
                <button
                  type="submit"
                  className="flex-1 rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700"
                >
                  Start Scan
                </button>
                <button
                  type="button"
                  onClick={() => setShowTriggerModal(false)}
                  className="flex-1 rounded-lg border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
