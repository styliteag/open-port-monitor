import { type ButtonHTMLAttributes, forwardRef } from 'react'

type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'

const variantStyles: Record<ButtonVariant, string> = {
  primary:
    'rounded-full border border-slate-900 bg-slate-900 px-5 py-2 text-xs font-semibold text-white transition hover:-translate-y-0.5 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-70 dark:border-white dark:bg-white dark:text-slate-900 dark:hover:bg-slate-200',
  secondary:
    'rounded-full border border-slate-200 px-4 py-2 text-xs font-semibold text-slate-600 transition hover:border-slate-300 hover:bg-slate-100 dark:border-slate-800 dark:text-slate-300 dark:hover:border-slate-700 dark:hover:bg-slate-900',
  ghost:
    'rounded-full px-4 py-2 text-xs font-semibold text-slate-600 transition hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800',
  danger:
    'rounded-full border border-rose-600 bg-rose-600 px-5 py-2 text-xs font-semibold text-white transition hover:-translate-y-0.5 hover:bg-rose-700 disabled:cursor-not-allowed disabled:opacity-70',
}

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', className = '', children, ...props }, ref) => (
    <button ref={ref} className={`${variantStyles[variant]} ${className}`} {...props}>
      {children}
    </button>
  ),
)

Button.displayName = 'Button'

export default Button
