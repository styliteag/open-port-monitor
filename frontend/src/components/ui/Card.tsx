import { type HTMLAttributes, forwardRef } from 'react'

type CardVariant = 'default' | 'glass' | 'flush' | 'page' | 'section' | 'item' | 'info'

const variantStyles: Record<CardVariant, string> = {
  default:
    'rounded-2xl border border-slate-200/70 bg-white/80 p-5 shadow-sm dark:border-slate-800/70 dark:bg-slate-900/70',
  glass:
    'rounded-3xl border border-slate-200/60 bg-white/80 p-8 shadow-[0_20px_80px_rgba(15,23,42,0.12)] backdrop-blur dark:border-slate-800/60 dark:bg-slate-950/70',
  flush:
    'rounded-2xl border border-slate-200/70 bg-slate-50/80 p-4 dark:border-slate-800/70 dark:bg-slate-900/60',
  // Aliases for sub-agent compatibility
  page: 'rounded-xl border border-slate-200/70 bg-white/80 p-8 shadow-[0_20px_80px_rgba(15,23,42,0.12)] backdrop-blur dark:border-slate-800/70 dark:bg-slate-950/70',
  section:
    'rounded-xl border border-slate-200/70 bg-white/80 p-6 shadow-sm dark:border-slate-800/70 dark:bg-slate-950/70',
  item: 'rounded-xl border border-slate-200/70 bg-white/80 p-4 shadow-sm dark:border-slate-800/70 dark:bg-slate-900/60',
  info: 'rounded-xl border border-slate-200/70 bg-slate-50/80 px-4 py-3 dark:border-slate-800/80 dark:bg-slate-900/60',
}

interface CardProps extends HTMLAttributes<HTMLDivElement> {
  variant?: CardVariant
  hover?: boolean
}

const Card = forwardRef<HTMLDivElement, CardProps>(
  ({ variant = 'default', hover = false, className = '', children, ...props }, ref) => (
    <div
      ref={ref}
      className={`${variantStyles[variant]} ${hover ? 'transition duration-300 hover:-translate-y-1 hover:shadow-lg' : ''} ${className}`}
      {...props}
    >
      {children}
    </div>
  ),
)

Card.displayName = 'Card'

export default Card
