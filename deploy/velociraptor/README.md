# deploy/velociraptor

Velociraptor server/client 部署相關檔案,對應規格〈Velociraptor 部署〉章節,於
**Phase 1** 補完:

- `server.config.yaml` / `client.config.yaml`(由 `velociraptor config generate` /
  `velociraptor config client` 產生,不進版控——含憑證與 server 位址,放這裡的應是
  範本/佔位版本,實際機密設定另行管理)
- MSI 打包腳本
- GPO 推送流程文件(`Velociraptor-Agent-Deploy` GPO 設定步驟)
- 部署驗證 Checklist
- 核心 Artifact 清單(`Generic.Client.Info`、`Windows.EventLogs.Defender`、
  `Windows.Remediation.Quarantine` 等)

Server 部署位置(VM 規格/備份策略)待 Phase 1 開工前與使用者確認實際基礎設施。
