/**
 * Shared date formatting utilities.
 * Extracted to avoid duplication across pages.
 */

export const formatDateTime = (value: Date) =>
  new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(value)

export const parseUtcDate = (dateStr: string) =>
  new Date(dateStr.endsWith('Z') ? dateStr : dateStr + 'Z')

export const formatRelativeTime = (value: Date, now: Date) => {
  const diffMs = now.getTime() - value.getTime()
  if (diffMs < 0) return 'Just now'
  const minutes = Math.floor(diffMs / 60000)
  if (minutes < 1) return 'Just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}
