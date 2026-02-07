import { type HTMLAttributes, forwardRef } from 'react'

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  /** Tailwind color classes for border/bg/text, e.g. from ALERT_TYPE_STYLES */
  colorClasses?: string
}

const Badge = forwardRef<HTMLSpanElement, BadgeProps>(
  ({ colorClasses = '', className = '', children, ...props }, ref) => (
    <span
      ref={ref}
      className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold tracking-wide ${colorClasses} ${className}`}
      {...props}
    >
      {children}
    </span>
  ),
)

Badge.displayName = 'Badge'

export default Badge
