interface PageHeaderProps {
  subtitle: string
  title: string
  description?: string
  children?: React.ReactNode
}

const PageHeader = ({ subtitle, title, description, children }: PageHeaderProps) => (
  <div className="flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
    <div>
      <p className="text-xs font-semibold text-slate-500 dark:text-slate-400">{subtitle}</p>
      <h2 className="mt-3 font-display text-3xl text-slate-900 dark:text-white">{title}</h2>
      {description && (
        <p className="mt-2 max-w-2xl text-sm text-slate-600 dark:text-slate-300">{description}</p>
      )}
    </div>
    {children && <div className="flex flex-wrap items-center gap-3">{children}</div>}
  </div>
)

export default PageHeader
