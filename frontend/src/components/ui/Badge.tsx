import { type HTMLAttributes, forwardRef } from 'react'

type BadgeVariant = 'default' | 'success' | 'warning' | 'danger' | 'info' | 'muted'

const variantStyles: Record<BadgeVariant, string> = {
  default:
    'border-slate-200 bg-white text-slate-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300',
  success:
    'border-emerald-400/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-200',
  warning:
    'border-amber-400/40 bg-amber-500/15 text-amber-700 dark:text-amber-200',
  danger:
    'border-rose-400/40 bg-rose-500/15 text-rose-700 dark:text-rose-200',
  info:
    'border-cyan-400/40 bg-cyan-500/15 text-cyan-700 dark:text-cyan-200',
  muted:
    'border-slate-300/60 bg-slate-200/40 text-slate-600 dark:border-slate-600/60 dark:bg-slate-800/60 dark:text-slate-300',
}

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant
  /** Override variant with raw Tailwind classes */
  colorClasses?: string
}

const Badge = forwardRef<HTMLSpanElement, BadgeProps>(
  ({ variant = 'default', colorClasses, className = '', children, ...props }, ref) => (
    <span
      ref={ref}
      className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold tracking-wide ${colorClasses ?? variantStyles[variant]} ${className}`}
      {...props}
    >
      {children}
    </span>
  ),
)

Badge.displayName = 'Badge'

export default Badge
