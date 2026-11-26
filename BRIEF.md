# imk-aac 開發簡報

這份簡報交給在本 repo 新開的 Claude Code session。內容自成一體，不依賴原對話。

## 你的角色與這次的範圍

- 角色：coordinator。這次只做開發前的準備，不寫程式。
- 要做的事：
  1. 用 `obw:pm` skill 為本 repo 設定 Obsidian workspace。
  2. 把下面的 M0 到 M4 建成 obw 的任務卡，每張卡寫明目標、完成條件，以及還有哪些部分是 stub。
  3. 回報任務卡的位置，然後停下來，等使用者決定從哪個 milestone 開始。
- 監督方式：使用者直接在這個 Rex session 和你互動，問題直接問使用者。

## 目標

在 Mac mini 上寫一支 Rust 常駐程式，取代 `aac listen`，需求如下：

- 開機時摸一下 immurok 指紋鑰匙，就能解鎖 Bitwarden vault。
- 每個 `aac run` 請求都要摸 immurok 才放行，不用再回終端機按 `y`。
- vault 裡查不到項目時，先 `bw sync` 再查一次。
- 用 `aac run --id <item-id>:<欄位名>` 讀取 Bitwarden 的自訂欄位。
- 用 LaunchAgent 開機啟動，以 chezmoi 部署。部署設定放在另一個 repo：machine-manager。

請求端照樣用原版的 `aac run`，不需要修改。

## 已查證的事實

### aac（Bitwarden Agent Access）

- 上游：https://github.com/bitwarden/agent-access ，授權 Apache-2.0。本機版本 v0.11.0（2026-03-21）。專案還在 early preview，API 可能變動。
- `aac listen` 沒有自動核准或外部核准的選項，只能在它的 TUI 按 `y`（`aac listen --help`）。
- 上游的 `examples/rust-listener/src/main.rs` 只有 83 行，示範了 `UserClient::connect`、`get_psk_token`，以及處理 `UserClientRequest::CredentialRequest { query, reply }` 的迴圈。
- `ap-client` 0.11.0 有發布在 crates.io，要開 `native-websocket` feature。
- 配對資料存在 `~/.access-protocol/`，有 `identity.key`、`connection_cache_{name}.json`、`psk_store_{name}.json` 三種檔案。讀寫它們的程式碼在上游 `crates/ap-cli/src/storage/`，共三個檔案、約 530 行。照搬這些程式碼，就能沿用現有配對。
- 請求端用 `aac run --id` 時，id 字串原樣變成 `CredentialQuery::Id`，不做任何檢查（上游 `crates/ap-cli/src/command/run.rs` 第 136 行）。
- 上游的 Bitwarden provider（`crates/ap-cli/src/providers/bitwarden.rs`）有三個限制：
  - 只用 `bw get item` 讀 `login` 區塊（第 152–188 行）。
  - `notes` 寫死成 `None`。
  - 項目沒有 `login` 區塊就回傳找不到，而且從來不跑 `bw sync`。
- 協定的 `CredentialData` 只有 `username`、`password`、`totp`、`uri`、`notes`、`credential_id`、`domain` 這幾個欄位（`crates/ap-client/src/types.rs`）。上游 issue #160 要求支援自訂欄位，目前沒有維護者回應。
- 原版有「Remember this approval for X minutes」這個功能（上游 PR #110）。

### immurok（imk）

- `/usr/local/bin/imk` 歸 root 所有，跟著 immurok.app 1.6.10 一起安裝和更新。不要把它複製進本專案。
- `imk get imk://api/bitwarden` 摸了指紋之後，會輸出 Bitwarden master password。這把 key 已經建好了。
- `imk run --agent -- CMD` 會跳出 immurok 的驗證畫面，摸了才執行 CMD（`imk --help`）。本專案打算拿它當每個請求的核准關卡。
- **還沒驗證**：逾時、沒摸、用沒登記的手指時，exit code 會不會是非 0。這就是 M0 要測的。Linux 版的 `immurok-cli fp verify` 有前例，指紋不符時也回 exit 0。

### 現行做法

machine-manager repo 的 `home/dot_local/bin/executable_aac-listen.tmpl`（commit 3f71e20）是這樣做的：

1. 用絕對路徑 `/usr/local/bin/imk` 執行 `imk get`，取得 master password。
2. 用 `/opt/homebrew/bin/bw` 執行 `bw unlock --nointeraction --passwordenv BW_MASTER_PASSWORD --raw`，取得 session。
3. 執行 `BW_SESSION=... exec ~/.local/bin/aac listen`。

密碼只放在沒有 export 的變數裡，以 `set +x` 防止被印出來，stdin 也關閉。這些安全作法要沿用。

## 設計決定

- 用 Rust，直接依賴 `ap-client`，版本固定在 0.11.0。不做 GUI，核准畫面借用 immurok 的驗證視窗，錯誤寫進 log。
- 只接受已經用 PSK 配對過的連線，拒絕新的 rendezvous 配對。新配對需要人確認指紋，交給原版 `aac listen` 做。
- 已知風險：
  - 常駐之後，`BW_SESSION` 會從開機起一直留在記憶體裡。
  - 新工具不能和原版 `aac listen` 同時跑，兩者同時連上 relay 會發生什麼事，還沒查證。
  - 開機時 immurok 的 BLE 可能還沒連上，程式要能重試。

## Milestones

每個 milestone 只有一個可觀察的結果。

- **M0，實測核准關卡，不寫程式**：分三種情況跑 `imk run --agent -- /usr/bin/true`：摸對指紋、不摸等逾時、用沒登記的手指。完成條件是記下三種情況的 exit code，而且只有摸對時是 0。不符合的話，就要換一種關卡，並回報使用者。
- **M1，端到端骨架**：listener 沿用 `~/.access-protocol/` 的現有配對，查詢一律回固定的假憑證，但核准走 immurok。完成條件是從另一個 shell 跑 `aac run`，只有摸了才拿到值，不摸或摸錯都被拒絕。這個階段的 stub 是憑證來源。
- **M2，真的 vault**：改成用 `bw get item` 查詢。啟動時先用 imk 解鎖、跑一次 `bw sync`，查不到時再 sync 一次。完成條件是在其他裝置新增一個項目後，不重啟 listener 也能用 `aac run` 取到它。
- **M3，自訂欄位**：用 `--id <item>:<欄位名>` 回傳 `fields` 裡那個欄位的值，放在 password 位置。完成條件是 `aac run --id <item>:<欄位> --env X=password -- ...` 拿到的是該欄位的值。
- **M4，部署**：LaunchAgent 加上 machine-manager 的 chezmoi 設定。完成條件是重開機後摸一次 immurok，`aac run` 就能用。注意：修改 machine-manager，以及執行 `chezmoi apply`，都要先取得使用者同意。

## 不在範圍內

- 對上游 bitwarden/agent-access 發 PR。這件事另外處理。
