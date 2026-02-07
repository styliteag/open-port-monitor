import type { InputHTMLAttributes, SelectHTMLAttributes } from 'react'

const inputBase =
  'w-full rounded-2xl border border-slate-200/70 bg-white px-4 py-2 text-sm font-medium text-slate-900 shadow-sm focus:border-cyan-400 focus:outline-none dark:border-slate-800 dark:bg-slate-900 dark:text-slate-100'

const labelBase = 'space-y-2 text-xs font-semibold text-slate-500 dark:text-slate-400'

interface InputFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string
  hint?: string
}

export const InputField = ({ label, hint, className = '', ...props }: InputFieldProps) => (
  <label className={labelBase}>
    {label}
    <input className={`${inputBase} ${className}`} {...props} />
    {hint && (
      <span className="text-[11px] font-medium text-slate-400 dark:text-slate-500">{hint}</span>
    )}
  </label>
)

interface SelectFieldProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label: string
  hint?: string
  options: Array<{ value: string; label: string; disabled?: boolean }>
}

export const SelectField = ({ label, hint, options, className = '', ...props }: SelectFieldProps) => (
  <label className={labelBase}>
    {label}
    <select className={`${inputBase} ${className}`} {...props}>
      {options.map((opt) => (
        <option key={opt.value} value={opt.value} disabled={opt.disabled}>
          {opt.label}
        </option>
      ))}
    </select>
    {hint && (
      <span className="text-[11px] font-medium text-slate-400 dark:text-slate-500">{hint}</span>
    )}
  </label>
)
