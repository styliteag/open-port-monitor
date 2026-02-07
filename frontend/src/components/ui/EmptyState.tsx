interface EmptyStateProps {
  message: string
  variant?: 'default' | 'error'
}

const styles = {
  default:
    'rounded-xl border border-slate-200/70 bg-slate-50/80 px-4 py-3 text-sm text-slate-500 dark:border-slate-800/70 dark:bg-slate-900/60 dark:text-slate-400',
  error:
    'rounded-xl border border-rose-200/70 bg-rose-50/80 px-4 py-3 text-sm text-rose-700 dark:border-rose-500/40 dark:bg-rose-500/10 dark:text-rose-100',
}

const EmptyState = ({ message, variant = 'default' }: EmptyStateProps) => (
  <div className={styles[variant]}>{message}</div>
)

export default EmptyState
