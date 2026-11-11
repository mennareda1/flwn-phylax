// Tailwind carries the Flwn tokens (SKILL.md section 10). The same values live in src/tokens.css, which is the single source: scripts/brand-check.mjs fails if they drift.
/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  future: { hoverOnlyWhenSupported: true },
  theme: {
    screens: { sm: '40rem', md: '48rem', lg: '64rem', xl: '80rem', '2xl': '96rem' },
    extend: {
      colors: {
        cream: '#F7F3EA',
        white: '#FFFFFF',
        navy: '#001F55',
        ink: { DEFAULT: '#14131A', soft: '#6B6875', 72: 'rgba(20, 19, 26, 0.72)' },   // 72: secondary text on pastel cards (--ink-72)
        pastel: { green: '#B3E3C4', lavender: '#E3D3FA', gold: '#F8DB99', salmon: '#F5B3AC', blue: '#ABE1EA' },
        line: '#E0DDD5',
        grid: '#D3CFC9',
      },
      borderRadius: { 'flwn-sm': '0.375rem', flwn: '0.625rem' },
      borderWidth: { hair: '1.5px' },
      boxShadow: { flwn: '0 0.125rem 0 rgba(20,19,26,.06), 0 0.5rem 1.125rem rgba(20,19,26,.08)' },
      transitionDuration: { fast: 'var(--dur-fast)', DEFAULT: 'var(--dur)', slow: 'var(--dur-slow)' },
      transitionTimingFunction: { out: 'var(--ease-out)', in: 'var(--ease-in)', 'in-out': 'var(--ease-in-out)' },
      fontFamily: { sans: ['"Plus Jakarta Sans"', 'Inter', 'system-ui', 'sans-serif'], mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'] },
      maxWidth: { page: '100rem' },
    },
  },
};
