import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useAuth } from '../context/AuthContext'
import { API_BASE_URL, extractErrorMessage, fetchJson, getAuthHeaders } from '../lib/api'
import type {
  Scanner,
  ScannerCreateResponse,
  ScannerListResponse,
  ScannerRegenerateKeyResponse,
} from '../types'
import { Card, Badge, Button, PageHeader, EmptyState, StatusDot, Modal } from '../components/ui'

const formatDateTime = (value: Date) =>
  new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(value)

const formatRelativeTime = (value: Date, now: Date) => {
  const diffMs = now.getTime() - value.getTime()
  if (diffMs < 0) return 'Just now'
  const minutes = Math.floor(diffMs / 60000)
  if (minutes < 1) return 'Just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

const parseUtcDate = (dateStr: string) => {
  return new Date(dateStr.endsWith('Z') ? dateStr : dateStr + 'Z')
}

const isOnline = (lastSeenAt: string | null, now: Date) => {
  if (!lastSeenAt) return false
  const lastSeen = parseUtcDate(lastSeenAt)
  return now.getTime() - lastSeen.getTime() < 5 * 60 * 1000
}

const inputClass =
  'w-full rounded-xl border border-slate-200/70 bg-white px-4 py-2 text-sm font-medium text-slate-900 shadow-sm focus:border-cyan-400 focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100'

const Scanners = () => {
  const { token, user } = useAuth()
  const queryClient = useQueryClient()
  const now = new Date()

  const [showCreate, setShowCreate] = useState(false)
  const [showEdit, setShowEdit] = useState(false)
  const [showDelete, setShowDelete] = useState(false)
  const [showRegenerate, setShowRegenerate] = useState(false)
  const [showApiKey, setShowApiKey] = useState(false)

  const [createForm, setCreateForm] = useState({ name: '', description: '' })
  const [editForm, setEditForm] = useState({ name: '', description: '' })
  const [selectedScanner, setSelectedScanner] = useState<Scanner | null>(null)
  const [displayedApiKey, setDisplayedApiKey] = useState<string | null>(null)
  const [formError, setFormError] = useState<string | null>(null)
  const [copySuccess, setCopySuccess] = useState(false)

  const scannersQuery = useQuery({
    queryKey: ['scanners'],
    queryFn: () => fetchJson<ScannerListResponse>('/api/scanners', token ?? ''),
    enabled: Boolean(token),
  })

  const createScannerMutation = useMutation({
    mutationFn: async (payload: { name: string; description: string | null }) => {
      const response = await fetch(`${API_BASE_URL}/api/scanners`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(token ?? '') },
        body: JSON.stringify(payload),
      })
      if (!response.ok) throw new Error(await extractErrorMessage(response))
      return response.json() as Promise<ScannerCreateResponse>
    },
    onSuccess: async (data) => {
      setShowCreate(false)
      setFormError(null)
      setCreateForm({ name: '', description: '' })
      setDisplayedApiKey(data.api_key)
      setShowApiKey(true)
      await queryClient.invalidateQueries({ queryKey: ['scanners'] })
    },
    onError: (error) => {
      setFormError(error instanceof Error ? error.message : 'Failed to create scanner')
    },
  })

  const updateScannerMutation = useMutation({
    mutationFn: async (payload: {
      scannerId: number
      name: string | null
      description: string | null
    }) => {
      const response = await fetch(`${API_BASE_URL}/api/scanners/${payload.scannerId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders(token ?? '') },
        body: JSON.stringify({ name: payload.name, description: payload.description }),
      })
      if (!response.ok) throw new Error(await extractErrorMessage(response))
      return response.json()
    },
    onSuccess: async () => {
      setShowEdit(false)
      setFormError(null)
      setSelectedScanner(null)
      await queryClient.invalidateQueries({ queryKey: ['scanners'] })
    },
    onError: (error) => {
      setFormError(error instanceof Error ? error.message : 'Failed to update scanner')
    },
  })

  const deleteScannerMutation = useMutation({
    mutationFn: async (scannerId: number) => {
      const response = await fetch(`${API_BASE_URL}/api/scanners/${scannerId}`, {
        method: 'DELETE',
        headers: getAuthHeaders(token ?? ''),
      })
      if (!response.ok) throw new Error(await extractErrorMessage(response))
    },
    onSuccess: async () => {
      setShowDelete(false)
      setFormError(null)
      setSelectedScanner(null)
      await queryClient.invalidateQueries({ queryKey: ['scanners'] })
    },
    onError: (error) => {
      setFormError(error instanceof Error ? error.message : 'Failed to delete scanner')
    },
  })

  const regenerateKeyMutation = useMutation({
    mutationFn: async (scannerId: number) => {
      const response = await fetch(`${API_BASE_URL}/api/scanners/${scannerId}/regenerate-key`, {
        method: 'POST',
        headers: getAuthHeaders(token ?? ''),
      })
      if (!response.ok) throw new Error(await extractErrorMessage(response))
      return response.json() as Promise<ScannerRegenerateKeyResponse>
    },
    onSuccess: async (data) => {
      setShowRegenerate(false)
      setFormError(null)
      setSelectedScanner(null)
      setDisplayedApiKey(data.api_key)
      setShowApiKey(true)
      await queryClient.invalidateQueries({ queryKey: ['scanners'] })
    },
    onError: (error) => {
      setFormError(error instanceof Error ? error.message : 'Failed to regenerate API key')
    },
  })

  const scanners = scannersQuery.data?.scanners ?? []
  const isAdmin = user?.role === 'admin'

  const openCreateModal = () => {
    setFormError(null)
    setCreateForm({ name: '', description: '' })
    setShowCreate(true)
  }

  const openEditModal = (scanner: Scanner) => {
    setFormError(null)
    setSelectedScanner(scanner)
    setEditForm({ name: scanner.name, description: scanner.description ?? '' })
    setShowEdit(true)
  }

  const openDeleteModal = (scanner: Scanner) => {
    setFormError(null)
    setSelectedScanner(scanner)
    setShowDelete(true)
  }

  const openRegenerateModal = (scanner: Scanner) => {
    setFormError(null)
    setSelectedScanner(scanner)
    setShowRegenerate(true)
  }

  const handleCreateSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setFormError(null)
    if (!token) {
      setFormError('Authentication required to create a scanner.')
      return
    }
    createScannerMutation.mutate({
      name: createForm.name.trim(),
      description: createForm.description.trim() || null,
    })
  }

  const handleEditSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setFormError(null)
    if (!token || !selectedScanner) {
      setFormError('Authentication required to update scanner.')
      return
    }
    updateScannerMutation.mutate({
      scannerId: selectedScanner.id,
      name: editForm.name.trim() || null,
      description: editForm.description.trim() || null,
    })
  }

  const handleDeleteConfirm = () => {
    if (!token || !selectedScanner) {
      setFormError('Authentication required to delete scanner.')
      return
    }
    deleteScannerMutation.mutate(selectedScanner.id)
  }

  const handleRegenerateConfirm = () => {
    if (!token || !selectedScanner) {
      setFormError('Authentication required to regenerate API key.')
      return
    }
    regenerateKeyMutation.mutate(selectedScanner.id)
  }

  const copyApiKey = async () => {
    if (displayedApiKey) {
      await navigator.clipboard.writeText(displayedApiKey)
      setCopySuccess(true)
      setTimeout(() => setCopySuccess(false), 2000)
    }
  }

  const closeApiKeyModal = () => {
    setShowApiKey(false)
    setDisplayedApiKey(null)
    setCopySuccess(false)
  }

  const ErrorBanner = ({ message }: { message: string | null }) =>
    message ? (
      <div className="mt-4 rounded-xl border border-rose-200/70 bg-rose-50/80 px-4 py-3 text-sm text-rose-700 dark:border-rose-500/40 dark:bg-rose-500/10 dark:text-rose-100">
        {message}
      </div>
    ) : null

  return (
    <div className="relative">
      <div className="pointer-events-none absolute -left-16 top-8 h-64 w-64 animate-drift rounded-full bg-violet-500/15 blur-[120px]" />
      <div className="pointer-events-none absolute right-8 top-36 h-64 w-64 animate-drift rounded-full bg-cyan-500/15 blur-[140px]" />

      <section className="relative z-10 space-y-6">
        <Card variant="page" className="animate-rise">
          <PageHeader
            subtitle="Scanners"
            title="Scanner locations"
            description="Manage scanner scanners and monitor their connection status. Each scanner runs a scanner that communicates with the backend using its API key."
          >
            <Card variant="info" className="text-xs text-slate-500 shadow-sm dark:text-slate-300">
              {scannersQuery.isLoading
                ? 'Refreshing scanners...'
                : `Updated ${formatDateTime(now)}`}
            </Card>
            {isAdmin ? (
              <Button onClick={openCreateModal}>Create Scanner</Button>
            ) : null}
          </PageHeader>

          <div className="mt-8 overflow-hidden rounded-xl border border-slate-200/70 bg-white/80 shadow-sm dark:border-slate-800/70 dark:bg-slate-900/60">
            <div className="grid grid-cols-1 gap-4 border-b border-slate-200/70 bg-slate-50/80 px-5 py-4 text-xs font-semibold text-slate-500 dark:border-slate-800/70 dark:bg-slate-900/60 dark:text-slate-300 md:grid-cols-[1.5fr_2fr_0.8fr_1fr_1fr_0.8fr]">
              <span>Name</span>
              <span>Description</span>
              <span>Version</span>
              <span>Last seen</span>
              <span>Status</span>
              <span className="text-right">Actions</span>
            </div>
            <div className="divide-y divide-slate-200/70 dark:divide-slate-800/70">
              {scannersQuery.isError ? (
                <div className="px-6 py-6 text-sm text-rose-600 dark:text-rose-200">
                  Unable to load scanners right now.
                </div>
              ) : scanners.length === 0 ? (
                <div className="px-6 py-6">
                  <EmptyState message="No scanners have been added yet." />
                </div>
              ) : (
                scanners.map((scanner) => {
                  const online = isOnline(scanner.last_seen_at, now)
                  const lastSeenDate = scanner.last_seen_at
                    ? parseUtcDate(scanner.last_seen_at)
                    : null
                  const lastSeenLabel = lastSeenDate
                    ? formatRelativeTime(lastSeenDate, now)
                    : 'Never'
                  const lastSeenDetail = lastSeenDate
                    ? formatDateTime(lastSeenDate)
                    : 'No scanner connection recorded'

                  return (
                    <div
                      key={scanner.id}
                      className="grid grid-cols-1 gap-4 px-5 py-4 text-sm md:grid-cols-[1.5fr_2fr_0.8fr_1fr_1fr_0.8fr]"
                    >
                      <div>
                        <p className="font-semibold text-slate-900 dark:text-white">
                          {scanner.name}
                        </p>
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          ID: {scanner.id}
                        </p>
                      </div>
                      <div className="text-slate-600 dark:text-slate-300">
                        {scanner.description || (
                          <span className="text-slate-400 dark:text-slate-500">No description</span>
                        )}
                      </div>
                      <div className="text-slate-600 dark:text-slate-300">
                        {scanner.scanner_version || (
                          <span className="text-slate-400 dark:text-slate-500">unknown</span>
                        )}
                      </div>
                      <div>
                        <p className="text-slate-700 dark:text-slate-200">{lastSeenLabel}</p>
                        <p className="text-xs text-slate-500 dark:text-slate-400">
                          {lastSeenDetail}
                        </p>
                      </div>
                      <div className="flex items-center">
                        <Badge
                          colorClasses={
                            online
                              ? 'border-emerald-300/50 bg-emerald-500/15 text-emerald-700 dark:border-emerald-400/40 dark:bg-emerald-500/20 dark:text-emerald-200'
                              : 'border-slate-300/60 bg-slate-200/40 text-slate-600 dark:border-slate-600/60 dark:bg-slate-800/60 dark:text-slate-300'
                          }
                          className="gap-2"
                        >
                          <StatusDot online={online} />
                          {online ? 'Online' : 'Offline'}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-end gap-2">
                        {isAdmin ? (
                          <>
                            <button
                              type="button"
                              onClick={() => openEditModal(scanner)}
                              className="rounded-lg border border-slate-200 px-2 py-1 text-xs font-medium text-slate-600 transition hover:border-slate-300 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:border-slate-600 dark:hover:bg-slate-800"
                            >
                              Edit
                            </button>
                            <button
                              type="button"
                              onClick={() => openRegenerateModal(scanner)}
                              className="rounded-lg border border-amber-200 px-2 py-1 text-xs font-medium text-amber-700 transition hover:border-amber-300 hover:bg-amber-50 dark:border-amber-700 dark:text-amber-300 dark:hover:border-amber-600 dark:hover:bg-amber-900/30"
                            >
                              Key
                            </button>
                            <button
                              type="button"
                              onClick={() => openDeleteModal(scanner)}
                              className="rounded-lg border border-rose-200 px-2 py-1 text-xs font-medium text-rose-700 transition hover:border-rose-300 hover:bg-rose-50 dark:border-rose-700 dark:text-rose-300 dark:hover:border-rose-600 dark:hover:bg-rose-900/30"
                            >
                              Delete
                            </button>
                          </>
                        ) : (
                          <span className="text-xs text-slate-400 dark:text-slate-500">
                            View only
                          </span>
                        )}
                      </div>
                    </div>
                  )
                })
              )}
            </div>
          </div>
        </Card>
      </section>

      {/* Create Scanner Modal */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Add a scanner location" subtitle="Create scanner">
        <form className="space-y-4" onSubmit={handleCreateSubmit}>
          <label className="block space-y-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
            Name
            <input
              type="text"
              required
              value={createForm.name}
              onChange={(e) => setCreateForm((prev) => ({ ...prev, name: e.target.value }))}
              className={inputClass}
              placeholder="HQ Scanner"
            />
          </label>
          <label className="block space-y-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
            Description (optional)
            <textarea
              value={createForm.description}
              onChange={(e) => setCreateForm((prev) => ({ ...prev, description: e.target.value }))}
              className={inputClass}
              placeholder="Main office scanner running on VM-01"
              rows={3}
            />
          </label>
          <ErrorBanner message={formError} />
          <div className="flex flex-wrap items-center justify-end gap-3">
            <Button variant="secondary" type="button" onClick={() => setShowCreate(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={createScannerMutation.isPending}>
              {createScannerMutation.isPending ? 'Creating...' : 'Create scanner'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Edit Scanner Modal */}
      <Modal open={showEdit && !!selectedScanner} onClose={() => setShowEdit(false)} title={`Update ${selectedScanner?.name ?? ''}`} subtitle="Edit scanner">
        <form className="space-y-4" onSubmit={handleEditSubmit}>
          <label className="block space-y-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
            Name
            <input
              type="text"
              required
              value={editForm.name}
              onChange={(e) => setEditForm((prev) => ({ ...prev, name: e.target.value }))}
              className={inputClass}
            />
          </label>
          <label className="block space-y-2 text-xs font-semibold text-slate-500 dark:text-slate-400">
            Description (optional)
            <textarea
              value={editForm.description}
              onChange={(e) => setEditForm((prev) => ({ ...prev, description: e.target.value }))}
              className={inputClass}
              rows={3}
            />
          </label>
          <ErrorBanner message={formError} />
          <div className="flex flex-wrap items-center justify-end gap-3">
            <Button variant="secondary" type="button" onClick={() => setShowEdit(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={updateScannerMutation.isPending}>
              {updateScannerMutation.isPending ? 'Saving...' : 'Save changes'}
            </Button>
          </div>
        </form>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal open={showDelete && !!selectedScanner} onClose={() => setShowDelete(false)} title={`Delete ${selectedScanner?.name ?? ''}?`} subtitle="Confirm deletion" maxWidth="max-w-md">
        <p className="text-sm text-slate-600 dark:text-slate-300">
          This action cannot be undone. All networks assigned to this scanner will also be
          deleted along with their scan history.
        </p>
        <ErrorBanner message={formError} />
        <div className="mt-6 flex flex-wrap items-center justify-end gap-3">
          <Button variant="secondary" onClick={() => setShowDelete(false)}>
            Cancel
          </Button>
          <Button
            variant="danger"
            onClick={handleDeleteConfirm}
            disabled={deleteScannerMutation.isPending}
          >
            {deleteScannerMutation.isPending ? 'Deleting...' : 'Delete scanner'}
          </Button>
        </div>
      </Modal>

      {/* Regenerate API Key Confirmation Modal */}
      <Modal open={showRegenerate && !!selectedScanner} onClose={() => setShowRegenerate(false)} title={`Generate new key for ${selectedScanner?.name ?? ''}?`} subtitle="Regenerate API key" maxWidth="max-w-md">
        <p className="text-sm text-slate-600 dark:text-slate-300">
          The old API key will be immediately invalidated. You will need to update the scanner
          configuration with the new key.
        </p>
        <ErrorBanner message={formError} />
        <div className="mt-6 flex flex-wrap items-center justify-end gap-3">
          <Button variant="secondary" onClick={() => setShowRegenerate(false)}>
            Cancel
          </Button>
          <button
            type="button"
            onClick={handleRegenerateConfirm}
            disabled={regenerateKeyMutation.isPending}
            className="rounded-full border border-amber-600 bg-amber-600 px-5 py-2 text-xs font-semibold text-white transition hover:-translate-y-0.5 hover:bg-amber-700 disabled:cursor-not-allowed disabled:opacity-70"
          >
            {regenerateKeyMutation.isPending ? 'Generating...' : 'Regenerate key'}
          </button>
        </div>
      </Modal>

      {/* API Key Display Modal */}
      <Modal open={showApiKey && !!displayedApiKey} onClose={closeApiKeyModal} title="Save this key now" subtitle="API key generated">
        <p className="text-sm text-slate-600 dark:text-slate-300">
          This API key will only be shown once. Copy it now and store it securely. Use this
          key in your scanner's environment configuration.
        </p>

        <div className="mt-4 rounded-xl border border-slate-200/70 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center justify-between gap-3">
            <code className="flex-1 break-all font-mono text-sm text-slate-900 dark:text-slate-100">
              {displayedApiKey}
            </code>
            <button
              type="button"
              onClick={copyApiKey}
              className={`flex-shrink-0 rounded-lg border px-3 py-1.5 text-xs font-semibold transition ${
                copySuccess
                  ? 'border-emerald-300 bg-emerald-50 text-emerald-700 dark:border-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                  : 'border-slate-200 text-slate-600 hover:border-slate-300 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:border-slate-600 dark:hover:bg-slate-800'
              }`}
            >
              {copySuccess ? 'Copied!' : 'Copy'}
            </button>
          </div>
        </div>

        <div className="mt-6 flex items-center justify-end">
          <Button onClick={closeApiKeyModal}>Done</Button>
        </div>
      </Modal>
    </div>
  )
}

export default Scanners
