import { type HTMLAttributes, forwardRef } from 'react'

interface ModalProps extends HTMLAttributes<HTMLDivElement> {
  maxWidth?: string
}

const Modal = forwardRef<HTMLDivElement, ModalProps>(
  ({ maxWidth = 'max-w-lg', className = '', children, ...props }, ref) => (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 px-4 py-8">
      <div
        ref={ref}
        className={`w-full ${maxWidth} rounded-xl border border-slate-200/70 bg-white/95 p-6 shadow-2xl dark:border-slate-800/70 dark:bg-slate-950 ${className}`}
        {...props}
      >
        {children}
      </div>
    </div>
  ),
)

Modal.displayName = 'Modal'

export default Modal
