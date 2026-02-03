import { useQuery } from '@tanstack/react-query'
import React, { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { fetchJson } from '../lib/api'
import type { ServiceHostListResponse, ServiceHostSummary } from '../types'

const formatDateTime = (value: Date) =>
  new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(value)

const parseUtcDate = (dateStr: string) => new Date(dateStr.endsWith('Z') ? dateStr : dateStr + 'Z')

const Services = () => {
  const { token } = useAuth()
  const [networkFilter, setNetworkFilter] = useState<number | null>(null)
  const [serviceFilter, setServiceFilter] = useState('')
  const [serverFilter, setServerFilter] = useState('')
  const [selectedService, setSelectedService] = useState<ServiceHostSummary | null>(null)

  // Fetch services
  const servicesQuery = useQuery({
    queryKey: ['services', networkFilter, serviceFilter, serverFilter],
    queryFn: async () => {
      const params = new URLSearchParams()
      if (networkFilter) params.append('network_id', String(networkFilter))
      if (serviceFilter) params.append('service_name', serviceFilter)
      if (serverFilter) params.append('http_server', serverFilter)
      const queryString = params.toString()
      return fetchJson<ServiceHostListResponse>(
        `/api/services/hosts${queryString ? `?${queryString}` : ''}`,
        token ?? ''
      )
    },
    enabled: Boolean(token),
  })

  const services = servicesQuery.data?.services ?? []

  const handleRowClick = (service: ServiceHostSummary) => {
    setSelectedService(selectedService?.host_ip === service.host_ip && selectedService?.port === service.port ? null : service)
  }

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-slate-800 dark:text-slate-100">Service Scans</h1>
        <p className="text-slate-600 dark:text-slate-400 mt-1">
          HTTP and service details discovered via Nmap NSE scripts
        </p>
      </div>

      {/* Filters */}
      <div className="mb-4 grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
            Service Name
          </label>
          <input
            type="text"
            value={serviceFilter}
            onChange={(e) => setServiceFilter(e.target.value)}
            placeholder="Filter by service name..."
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-100"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">
            HTTP Server
          </label>
          <input
            type="text"
            value={serverFilter}
            onChange={(e) => setServerFilter(e.target.value)}
            placeholder="Filter by HTTP server..."
            className="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-slate-100"
          />
        </div>
      </div>

      {/* Services Table */}
      <div className="bg-white dark:bg-slate-800 rounded-lg shadow overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-200 dark:divide-slate-700">
            <thead className="bg-slate-50 dark:bg-slate-900">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Host
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Port
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Service
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  HTTP Title
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  HTTP Server
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Network
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Last Scanned
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-slate-800 divide-y divide-slate-200 dark:divide-slate-700">
              {services.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-6 py-4 text-center text-slate-500 dark:text-slate-400">
                    {servicesQuery.isLoading ? 'Loading...' : 'No service scan results found'}
                  </td>
                </tr>
              ) : (
                services.map((service) => (
                  <React.Fragment key={`${service.host_ip}-${service.port}`}>
                    <tr
                      onClick={() => handleRowClick(service)}
                      className="hover:bg-slate-50 dark:hover:bg-slate-700 cursor-pointer"
                    >
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-slate-900 dark:text-slate-100">
                        {service.host_ip}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-900 dark:text-slate-100">
                        {service.port}/{service.protocol}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-900 dark:text-slate-100">
                        <span className="px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">
                          {service.service_name || 'Unknown'}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-900 dark:text-slate-100 max-w-xs truncate">
                        {service.http_title || '—'}
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-900 dark:text-slate-100 max-w-xs truncate">
                        {service.http_server || '—'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-900 dark:text-slate-100">
                        {service.http_status ? (
                          <span
                            className={`px-2 py-1 text-xs font-semibold rounded-full ${
                              service.http_status >= 200 && service.http_status < 300
                                ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                                : service.http_status >= 300 && service.http_status < 400
                                ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                                : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                            }`}
                          >
                            {service.http_status}
                          </span>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-900 dark:text-slate-100">
                        {service.network_name ? (
                          <Link
                            to={`/networks/${service.network_id}`}
                            className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {service.network_name}
                          </Link>
                        ) : (
                          '—'
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500 dark:text-slate-400">
                        {formatDateTime(parseUtcDate(service.last_scanned))}
                      </td>
                    </tr>
                    {selectedService?.host_ip === service.host_ip &&
                      selectedService?.port === service.port && (
                        <tr>
                          <td colSpan={8} className="px-6 py-4 bg-slate-50 dark:bg-slate-900">
                            <div className="text-sm">
                              <h4 className="font-semibold text-slate-900 dark:text-slate-100 mb-2">
                                Service Details
                              </h4>
                              <div className="grid grid-cols-2 gap-4">
                                <div>
                                  <span className="font-medium text-slate-700 dark:text-slate-300">
                                    Service:
                                  </span>{' '}
                                  <span className="text-slate-900 dark:text-slate-100">
                                    {service.service_name || 'Unknown'}
                                  </span>
                                </div>
                                {service.http_title && (
                                  <div>
                                    <span className="font-medium text-slate-700 dark:text-slate-300">
                                      Page Title:
                                    </span>{' '}
                                    <span className="text-slate-900 dark:text-slate-100">
                                      {service.http_title}
                                    </span>
                                  </div>
                                )}
                                {service.http_server && (
                                  <div>
                                    <span className="font-medium text-slate-700 dark:text-slate-300">
                                      Server:
                                    </span>{' '}
                                    <span className="text-slate-900 dark:text-slate-100">
                                      {service.http_server}
                                    </span>
                                  </div>
                                )}
                                {service.http_status && (
                                  <div>
                                    <span className="font-medium text-slate-700 dark:text-slate-300">
                                      HTTP Status:
                                    </span>{' '}
                                    <span className="text-slate-900 dark:text-slate-100">
                                      {service.http_status}
                                    </span>
                                  </div>
                                )}
                              </div>
                              <div className="mt-2">
                                <Link
                                  to={`/scans/${service.last_scan_id}`}
                                  className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 text-sm"
                                  onClick={(e) => e.stopPropagation()}
                                >
                                  View scan details →
                                </Link>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                  </React.Fragment>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

export default Services
