interface StatusDotProps {
  online: boolean
}

const StatusDot = ({ online }: StatusDotProps) => (
  <span
    className={`h-2 w-2 rounded-full ${
      online ? 'animate-pulse bg-emerald-500' : 'bg-slate-400'
    }`}
  />
)

export default StatusDot
