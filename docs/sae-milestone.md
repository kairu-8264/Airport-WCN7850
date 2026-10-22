# WPA3-Personal/SAE 第1段階 — 実装範囲と検証

対象: https://github.com/razvanccr/AirportWCN7850

基点コミット: `c3f75e49deaeabeeb43ca1f456f4271d4cd33121`

本変更はSAE接続を実現するものではない。SAEの識別と未実装経路の明示的拒否を実装し、次段階のためにWPA2との境界を明確にする。kext完成品は配布しない。元リポジトリへのpushは実施していない。

## コード変更

- `ieee80211_crypto.h`: SAE / FT-SAEに独立したAKMビットを定義。スキャン解析用であり、PSK・SHA256-PSKとして扱わない。
- `ieee80211_input.c`: RSN OUI `00:0f:ac` のAKM 8/9を認識。Microsoft WPA OUIの8/9は未対応のまま。未知OUI・未知AKMはNONEを維持。
- `AirportItlwmSkywalkInterface.cpp`: 明示的SAE要求を接続状態変更前にUnsupportedで拒否。補助関数にも入口ガードを追加し、非WCLのSAE→WPA2読み替えを削除。nullチェックを既存ログ参照より前に移動。
- `WCL.cpp`: SAE/FT-SAEビットを含む要求を、現在の接続切断・非同期延期・鍵導出より前に拒否し、要求中の鍵を消去。既存分類器もこれらを拒否していたが、拒否理由と境界を明示した。
- `AirportItlwmV2.cpp`: Tahoe WCLの保守的なcapabilityを維持する理由をコメント化。元から構造体がゼロ初期化され、WCLではSAE/PMFを有効にするビット設定がない。未確認のprivate capabilityビットを新設しない。非WCLの不明な定数群の意味までは検証していない。

SAEをローカル対応AKM一覧・RSN送信IE・PTK導出へ追加していない。既存のRSN AKM共通部分チェックにより、SAEだけのAPはローカル対応AKMと重ならない。WPA2/SAE混在APでは明示的なWPA2要求を従来どおり処理する。既存の `selectWPA2TransitionMode()` はスキャン通知のコピーだけを編集し、受信したRSN IEを変更しない。この処理は維持した。

SAEとPSK両方のビットが接続要求にある場合も拒否する。APの広告に両方式があることと、クライアントがSAEを要求したことは別である。明示的なSAE要求を勝手にPSKへ変更しない。

## 検証の再実行

```sh
python3 scripts/test-sae-milestone.py
# コンパイラを明示する場合
python3 scripts/test-sae-milestone.py --cxx clang++
git diff --check
```

スクリプトは静的契約4項目を検査し、C++コンパイラがあれば製品ソースから実際のAKM解析関数とenumを抽出してコンパイルする。WCL.hppからも対象の構造体・認証分類・スキャン処理関数を抽出し、WPA2分類、SAE/FT-SAE/PSK+SAE要求の拒否、混在APのスキャンコピー、PMF必須APとSAE専用APの非変換を検査する。AKM解析は3つのOUI×256番号を検査する。コンパイラなしの場合、実行テストをSKIPと明示する。WindowsではVisual Studioの開発環境を有効にして `--cxx cl.exe` も利用可能。

これはカーネル全体のビルド、WCL接続関数全体の実行、実機の無線通信試験ではない。ソース抽出テストの成功だけで、ABI・IOKit・タイミング・無線相互運用性は保証できない。

macOSのビルド手順:

```sh
scripts/fetch-firmware.sh
PRODUCT=AirportWCN7850 ./build.sh
DEBUG=1 PRODUCT=AirportWCN7850 ./build.sh build-debug
```

このWindows環境ではmacOSのxcrun/SDK/ld64によるkextビルドは未実施。WCN7850実機、Tahoe、APがないため、実接続やWPA2回帰も未検証。実行結果の確定値は同梱 `validation.txt` に記録する。

## 実機で必要な確認

1. 復旧可能な既存EFIを保持し、従来のWPA2-CCMP接続、DHCP、ARP、IPv6、再接続を比較する。
2. WPA2/SAE transition APではWPA2として接続できること、実際のAssociation RequestのAKMがPSKであることを別端末のキャプチャで確認する。
3. SAE専用AP、FT-SAE要求、SAE|PSK要求では認証・鍵交換を開始せず、Unsupportedを返すことを確認する。既存のWPA2接続中に拒否しても接続と鍵が変更されないことを確認する。
4. PMF必須のSAE APをWPA2接続可能と誤認しないこと、WCLがSAE能力を認識していないことを確認する。
5. 再起動・プライベートMAC変更中の延期・タイムアウトも回帰確認する。

## 次段階のSAE実装に必要なもの

SAEのCommit/Confirm状態機械、再送・中断・同時開始、anti-clogging token、group negotiation、反射/不正点/範囲の検査、定数時間のECC演算、秘密の消去が必要。パスワードの受け渡しも調べる必要がある。現在のWPA2経路でmacOSが渡す32-byte PMKからSAEパスワードは復元できず、そのPMKをSAE用として使うことはできない。

Hunting-and-Pecking/H2EとRSNXEの要件、PMK/PMKID生成、AKM=8のRSN送信、SAE用EAPOL/PTK処理、PMKSA管理、PMFとIGTK/BIP/SA Queryを一連で設計する。FT-SAEは別マイルストーンとする。既知テストベクトルとAP相互運用試験を通す前にcapabilityを有効にしない。暗号処理の空実装や成功だけ返すスケルトンは今回追加していない。

PMFの具体的な未解決点: `qwz_peer_assoc_h_crypto()` で `arg->is_pmf_enabled` の設定が `#if 0` 内にあり、`WMI_PEER_PMF` 生成経路へつながっていない。WMIフラグが定義済みというだけでは利用可能とは言えない。鍵install、IGTK、管理フレーム受信、firmware応答を実機で追う必要がある。

## その他の未対応項目の技術評価

| 項目 | 着手箇所と進め方 | 今回の判断 |
|---|---|---|
| 802.11ax | `qwz.c` のpeer association、HE capability、WCLのPHY報告を接続する。現在は非HE peer用HEMU=0の設定がある。HE IE解析、MCS/NSS、帯域、firmwareパラメータを段階的に検証する | まず5GHz/80MHz/単一リンクHEを別変更で検討。表示のビットを立てるだけでは不可 |
| 160/320MHz・be・MLO | チャネル表、regulatory、WMI PHY mode、帯域交渉、データパス、複数リンクの状態/鍵管理まで拡張が必要 | 80MHz HEの後。現時点では対応の約束はできない |
| sleep/wake | `AirportItlwmV2.cpp` のsetPowerState/Off/On、HALの停止/再初期化、`if_qwz_pci.c` のMHI/DMA/割込みを通して監査する | OffはdisableAdapterを呼ぶがOnは状態更新とacknowledgeだけで、再有効化の確認が必要。電源通知からfirmware再初期化、鍵破棄と再接続をログで追う。PCIのwake関数だけではOSスリープ対応にならない |
| multicast/TKIP group | `qwz.c` のcrypto_mode選択、set_key、REO/PN、RX descriptor/drop統計。ソースの既知不具合説明はWCN6855由来なので、WCN7850での条件を再現する | APのCCMP/TKIP group切替とfirmware比較を優先。フレームが割込みまで来なければ受信後のソフトウェア修正だけでは解決できない |
| 802.1X | WCLのenterprise PMK/MSK供給経路が既にある。EAP-TLS等のnative supplicantとの疎通、失敗時の鍵消去、再認証を検証 | SAEとは別試験。supplicantなしのEAP一式実装は小変更ではない |
| AWDL/AirDrop | 同梱 `docs/awdl-feasibility.md` は、firmwareの精密なチャネル切替/送信スケジュール不足を根拠にno-goと評価 | 能力広告やダミーawdl0だけは追加しない。firmware制約を覆す新しい証拠が必要 |

上記はこの基点ソースからの技術評価であり、新しい無線機能の実装・実機検証を完了したという意味ではない。
