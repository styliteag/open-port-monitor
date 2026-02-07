/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['var(--opm-sans)'],
        display: ['var(--opm-display)'],
      },
      colors: {
        opm: {
          ink: 'var(--opm-ink)',
          bg: 'var(--opm-bg)',
          card: 'var(--opm-card)',
        },
        tooltip: {
          bg: 'var(--tooltip-bg)',
          border: 'var(--tooltip-border)',
          text: 'var(--tooltip-text)',
        },
      },
    },
  },
  plugins: [],
}
