import type { ReactNode } from 'react'

interface ModalProps {
  open: boolean
  onClose: () => void
  title: string
  subtitle?: string
  children: ReactNode
  maxWidth?: string
}

const Modal = ({ open, onClose, title, subtitle, children, maxWidth = 'max-w-xl' }: ModalProps) => {
  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 px-4 py-8">
      <div
        className={`w-full ${maxWidth} rounded-3xl border border-slate-200/70 bg-white/95 p-6 shadow-2xl dark:border-slate-800/70 dark:bg-slate-950`}
      >
        <div className="flex items-start justify-between">
          <div>
            {subtitle && (
              <p className="text-xs font-semibold text-slate-500 dark:text-slate-400">{subtitle}</p>
            )}
            <h3 className="mt-2 font-display text-2xl text-slate-900 dark:text-white">{title}</h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-full border border-slate-200 px-3 py-1 text-xs font-semibold text-slate-600 transition hover:border-slate-300 hover:bg-slate-100 dark:border-slate-800 dark:text-slate-300 dark:hover:border-slate-700 dark:hover:bg-slate-900"
          >
            Close
          </button>
        </div>
        <div className="mt-6">{children}</div>
      </div>
    </div>
  )
}

export default Modal
