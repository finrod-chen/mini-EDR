export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className="logo-mark"
      aria-hidden="true"
    >
      <path
        d="M16 2.5L27.5 7.8V17.4C27.5 24.2 22.6 29.4 16 30.9C9.4 29.4 4.5 24.2 4.5 17.4V7.8L16 2.5Z"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <circle className="logo-ring logo-ring--outer" cx="16" cy="17" r="9" stroke="currentColor" strokeWidth="1.2" />
      <circle className="logo-ring logo-ring--inner" cx="16" cy="17" r="5.5" stroke="currentColor" strokeWidth="1.4" />
      <circle cx="16" cy="17" r="2.1" fill="currentColor" />
    </svg>
  )
}
