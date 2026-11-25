/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ['class', '[data-theme="dark"]'],
  content: [
    './components/**/*.{js,vue,ts}',
    './layouts/**/*.vue',
    './pages/**/*.vue',
    './plugins/**/*.{js,ts}',
    './app.vue'
  ],
  theme: {
    extend: {
      colors: {
        canvas: 'var(--bg)',
        card: 'var(--card)',
        tx: 'var(--tx)',
        field: 'var(--field)',
        act: 'var(--act)',
        sun: 'var(--sun)',
        mag: 'var(--mag)',
        ink: 'var(--ink)',
        line: 'var(--line)'
      },
      fontFamily: {
        sans: ['Outfit', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace']
      },
      boxShadow: {
        soft: 'var(--sh)',
        sticker: '2px 2px 0 var(--ink)'
      },
      borderRadius: {
        bento: '16px'
      },
      transitionTimingFunction: {
        spring: 'cubic-bezier(0.34, 1.56, 0.64, 1)'
      }
    }
  },
  plugins: []
}
