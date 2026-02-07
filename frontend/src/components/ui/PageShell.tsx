import type { ReactNode } from 'react'

interface PageShellProps {
  children: ReactNode
  blurs?: Array<{ color: string; position: string; size?: string }>
}

const defaultBlurs = [
  { color: 'bg-cyan-500/15', position: '-left-16 top-8', size: 'h-64 w-64 blur-[120px]' },
  { color: 'bg-emerald-500/15', position: 'right-8 top-36', size: 'h-64 w-64 blur-[140px]' },
]

const PageShell = ({ children, blurs = defaultBlurs }: PageShellProps) => {
  return (
    <div className="relative">
      {blurs.map((blur, i) => (
        <div
          key={i}
          className={`pointer-events-none absolute ${blur.position} ${blur.size ?? 'h-64 w-64 blur-[130px]'} animate-drift rounded-full ${blur.color}`}
        />
      ))}
      <section className="relative z-10 space-y-6">{children}</section>
    </div>
  )
}

export default PageShell
