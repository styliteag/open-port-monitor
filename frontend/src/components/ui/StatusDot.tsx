interface StatusDotProps {
  online: boolean
}

const StatusDot = ({ online }: StatusDotProps) => (
  <span
    className={`inline-block h-2 w-2 rounded-full ${
      online ? 'bg-emerald-500' : 'bg-slate-400 dark:bg-slate-600'
    }`}
  />
)

export default StatusDot
