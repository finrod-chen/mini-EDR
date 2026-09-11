export function LoadingOverlay({ label = '載入中…' }: { label?: string }) {
  return (
    <div className="loading-overlay">
      <span className="spinner spinner--lg" />
      {label}
    </div>
  )
}
