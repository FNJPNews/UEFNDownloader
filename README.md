# UEFN Cooked Content Helper

Epic Games / Fortnite の公開島に関するメタデータ確認、Content Service の調査、ローカルキャッシュや BuildPatchServices manifest の解析を行う Python 製 CLI ツールです。

> [!WARNING]
> このツールは研究・検証・自分が権限を持つコンテンツの調査を目的としています。Epic Games、Fortnite、UEFN とは非公式・非提携です。
> Epic Games の利用規約、Fan Content Policy、Fortnite / UEFN 関連ルール、各島・アセットの権利を必ず確認してください。
> 取得したトークン、device auth、ダウンロード済みコンテンツ、AES key、`.pak` / `.ucas` / `.utoc` / `.sig` などは公開しないでください。

## Features

- Epic OAuth ログインと保存済みセッションの更新
- device-code login による device auth 作成
- Fortnite / UEFN のマップコード正規化
- mnemonic メタデータの取得
- Content Service の probe
- Content Service v2 / v4 cooked-content-package の確認
- module key batch の確認
- `plugin.manifest` の取得
- BuildPatchServices manifest / chunk の解析と復元
- ローカル Fortnite ログから `plugin.manifest` URL 候補を抽出
- ローカル InstalledBundles キャッシュのエクスポート

## Requirements

- Python 3.10+
- Windows 推奨  
  一部機能は `%LOCALAPPDATA%\FortniteGame\Saved\...` を参照します。
- Epic Games アカウント
- 自分が利用規約上アクセスしてよいコンテンツ

外部 Python パッケージは使っていません。標準ライブラリのみで動作します。

## Installation

```bash
git clone https://github.com/<your-name>/<repo-name>.git
cd <repo-name>
python --version
```

必要に応じて仮想環境を作成します。

```bash
python -m venv .venv
.venv\Scripts\activate
```

## Quick Start

### 1. ログイン

```bash
python uefn_downloader.py login
```

ブラウザで Epic Games にログインし、表示されたコードまたはリダイレクト後の文字列を CLI に貼り付けます。

保存先の既定値は次の通りです。

```text
data/epic_auth_sessions.json
```

### 2. マップのメタデータを確認

```bash
python uefn_downloader.py resolve 0000-0000-0000
```

### 3. Content Service を probe

```bash
python uefn_downloader.py probe 0000-0000-0000
```

### 4. device-code login を使う場合

```bash
python uefn_downloader.py device-login
python uefn_downloader.py device-token
```

device auth は次に保存されます。

```text
data/device_auth.json
```

### 5. v2 cooked-content-package を確認

```bash
python uefn_downloader.py resolve-v2 0000-0000-0000
```

### 6. ローカル Fortnite ログから manifest URL を探す

```bash
python uefn_downloader.py scan-logs 0000-0000-0000
```

### 7. InstalledBundles キャッシュをエクスポート

```bash
python uefn_downloader.py export-bundle-cache 0000-0000-0000
```

### 8. 既知の manifest URL をダウンロード

```bash
python uefn_downloader.py download-manifest 0000-0000-0000 --manifest-url "https://example.com/plugin.manifest"
```

## Commands

| Command | Description |
| --- | --- |
| `login` | Epic OAuth セッションを保存 |
| `verify` | 保存済みまたは指定した bearer token を検証 |
| `refresh` | 保存済みセッションを更新・検証 |
| `token` | 保存済み access token を表示 |
| `logout` | 保存済みセッションを削除 |
| `device-login` | device-code flow で device auth を保存 |
| `device-token` | device auth から Content Service 向け token を表示 |
| `resolve` | mnemonic メタデータのみ取得 |
| `scan-logs` | Fortnite ログから manifest URL 候補を抽出 |
| `export-bundle-cache` | ローカル InstalledBundles の payload を出力 |
| `probe` | mnemonic 解決後に Content Service を調査 |
| `resolve-v2` | v2 cooked-content-package を確認 |
| `download` | v4 cooked-content-package と BPS chunks を使った取得処理 |
| `download-manifest` | manifest URL または各 ID から `plugin.manifest` を取得 |

詳細は以下で確認できます。

```bash
python uefn_downloader.py --help
python uefn_downloader.py download --help
```

## Output

既定では `downloads/<map-code>/` 以下に結果を保存します。

生成される可能性があるファイル例:

```text
downloads/
  0000-0000-0000/
    mnemonic.json
    public_modules.json
    content_service_probe.json
    artifact_candidates.json
    content_v2_cooked_content_package.json
    content_v4_client.json
    cooked_content_package.json
    plugin.manifest
    plugin.manifest.parsed.json
```

## Security Notes

GitHub に絶対にアップロードしないでください。

```text
data/
downloads/
deviceAuth.json
device_auth.json
epic_auth_sessions.json
*.pak
*.ucas
*.utoc
*.sig
*.manifest
*.chunk
module_key_v4.json
content_v2_cooked_content_package.json
content_v4_client.json
```

`token` / `deviceId` / `secret` / `refresh_token` / `access_token` / AES key が含まれるファイルは、漏洩すると Epic アカウントやコンテンツへの不正アクセスにつながる可能性があります。

## 謝辞・参考プロジェクト

本プロジェクトのEpic Games device-code認証、device authの作成・利用、
およびUEFN Content ServiceからAESキーを取得する仕組みの実装にあたり、
Krowe-moh氏の
[UEFN-AES-grabber](https://github.com/Krowe-moh/UEFN-AES-grabber)
を参考にしています。

参考元の処理をPython向けに再実装し、認証セッション管理、
Content Serviceの調査、manifestおよびBuildPatchServicesの解析などを
追加・変更しています。

UEFN-AES-grabberは
[Creative Commons Attribution-NonCommercial 4.0 International License](https://creativecommons.org/licenses/by-nc/4.0/)
で提供されています。

本プロジェクトはKrowe-moh氏、Epic Games、FortniteおよびUEFNとは
提携・承認関係にありません。

