import { useEffect, useState } from 'react'
import { apiGet } from './api'
import type { Asset } from './types'

// 監測到的 IP(防火牆封鎖清單的來源 IP、PA-410 syslog 告警的 host)如果剛好
// 是資產清單裡有登記的裝置,畫面上顯示資產的主機名會比一串數字好認得多。
// 只用 ip 當 key,資產清單筆數不大,直接一次抓全部在前端做對照,不用另開
// 一支後端查詢 API。
export function useAssetIpLookup(): Map<string, string> {
  const [lookup, setLookup] = useState<Map<string, string>>(new Map())

  useEffect(() => {
    apiGet<Asset[]>('/api/assets')
      .then((assets) => {
        const map = new Map<string, string>()
        for (const asset of assets) {
          if (asset.ip && asset.hostname) map.set(asset.ip, asset.hostname)
        }
        setLookup(map)
      })
      .catch(() => {
        // 資產清單載入失敗不影響原本頁面的主要功能,對不到名稱就顯示原始 IP。
      })
  }, [])

  return lookup
}
