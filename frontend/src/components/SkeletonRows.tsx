export function SkeletonRows({ rows = 5, columns }: { rows?: number; columns: number }) {
  return (
    <>
      {Array.from({ length: rows }).map((_, r) => (
        // eslint-disable-next-line react/no-array-index-key -- 純視覺佔位,沒有真實資料可當 key
        <tr key={r} className="row">
          {Array.from({ length: columns }).map((_, c) => (
            // eslint-disable-next-line react/no-array-index-key -- 同上
            <td key={c}>
              <div className="skeleton skeleton-text" style={{ width: `${58 + ((r + c) % 4) * 10}%` }} />
            </td>
          ))}
        </tr>
      ))}
    </>
  )
}
