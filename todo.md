# QuicHttpHandler TODO

YetAnotherHttpHandlerとの機能差、およびHTTP/3/QUIC固有の改善項目。

## P0: 正確性・リソース管理

- [x] キャンセル時に対象ストリームへ`RESET_STREAM(H3_REQUEST_CANCELLED)`を送信する
  - [x] C#キャンセルをnative actorへ通知し、`STOP_SENDING`と`RESET_STREAM`を送信する
  - C#のTaskだけでなく、QUICストリームとサーバー側処理を確実に停止する
  - [x] 応答ヘッダー受信前・受信後・アップロード中をそれぞれテストする（TUnit統合テスト）
- [x] レスポンストレーラーを`HttpResponseMessage.TrailingHeaders`へ反映する
  - [x] tokio-quicheへ1xxと区別されたtrailerイベントを実装する（nuskey8/quiche fork）
  - [x] 通常形式とgRPC形式のトレーラーをdriver testで検証する
  - [x] managed `HttpResponseMessage.TrailingHeaders`まで含むTUnit統合テストを追加する
- [x] GOAWAYを処理する
  - [x] 対象接続への新規要求投入を停止する
  - [x] 新しい接続へ切り替える
  - [x] GOAWAY ID以降の未処理要求を識別し、再試行可能な失敗として返す
  - [x] drain完了後に旧connection actorを終了し、poolから再利用されないようにする
  - [ ] 再送可能なbodyを導入後、未処理要求だけを自動再送する（P1「安全な自動リトライ」と共通）
- [x] 接続障害時の全リクエスト完了を保証する
  - [x] actor内の割当待ち・送受信中・キュー内要求をexactly-onceで完了する
  - [x] 完了callbackの16スレッド競合unit testを追加する
  - [x] peerによる接続切断で要求が未完了にならないことをTUnit統合テストする
  - [x] ハンドシェイク中、送信中、受信中、handler破棄との競合を統合テストする
- [x] HTTP/3 DATAGRAMを既定で無効化する
  - WebTransportまたはCONNECT-UDP利用時のみ明示的に有効化する

## P0: タイムアウトと接続確立

- [x] `ConnectTimeout`
- [x] `HandshakeTimeout`
- [x] `PooledConnectionIdleTimeout`
- [x] `PooledConnectionLifetime`
- [x] `DnsTimeout`
- [x] IPv6/IPv4 Happy Eyeballs
- [x] 複数A/AAAAレコードへのフォールバック
- [x] DNSキャッシュと`DnsRefreshTimeout`

## P0: Unity配布と検証

- [ ] Unity用`asmdef`と`.meta`を追加する
- [ ] 各プラットフォームのnative artifact配置を自動化する
  - Windows x64/arm64
  - macOS x64/arm64/universal
  - Linux x64/arm64
  - Android armv7/arm64/x64
  - iOS device/simulator
- [ ] Android 16 KiB page alignmentを検証する
- [ ] IL2CPP stripping設定を追加する
- [ ] Unity Editor/Mono/IL2CPP実機テストを追加する
- [ ] UPM package構造とNuGet package構造を整備する
- [ ] THIRD-PARTY-NOTICESを生成する

## P1: 接続プール

- [x] `MaxConnectionsPerServer`
- [x] peerのMAX_STREAMS枯渇時に別接続を作成する
- [x] アイドル接続のeviction
- [x] 接続障害を複数接続へ分散する
- [x] origin keyへTLS設定とSNI設定を正しく含める
- [x] handler破棄時に全接続と全ストリームを確実に終了する

- [x] GOAWAY、接続切断、`H3_REQUEST_REJECTED`を分類する

## P1: HTTP/3・QPACK

- [x] HTTP/3 header、QPACK、Extended CONNECT設定をhandlerへ公開する
- [x] informational response（1xx）を正しく処理する
- [x] HTTP/3エラーコードを保持した例外型を追加する
- [x] QUIC transport errorとHTTP/3 application errorを区別する

## P1: QUICフロー制御（`QuicTransportOptions`）

- [x] flow controlとsocket buffer設定を`QuicTransportOptions`へ集約する
- [x] `ResponsePipeOptions`
  - 現在の固定値256/128 KiBを設定可能にする

## P1: 証明書・TLS

- [x] `RootCertificates`を「既定ルートへ追加」と「置換」から選択可能にする
- [x] 証明書/SPKI pinningを検証callbackで実装できるようにする
- [x] 検証無効化を`DangerousAcceptAnyServerCertificateValidator`で明示する
- [x] 証明書callbackへ検証時刻と標準検証結果を渡す
- [ ] OCSP stapling情報を公開する（具体的な利用要求が出るまで保留）
- [ ] CRL/失効確認方針を設定可能にする（CRL供給APIと一体で設計する）
- [x] 証明書チェーン全体をcallbackへ渡せるようにする
- [x] mTLS証明書と秘密鍵の一致を設定時に検証する
- [x] TLS handshake errorを詳細なmanaged例外へ変換する

## P2: QUIC性能調整

- [x] `QuicTransportOptions`として上級設定を分離する
- [x] 輻輳制御アルゴリズム
  - Cubic
  - BBR系（対応ビルドのみ）
- [x] `InitialCongestionWindowPackets`
- [x] pacing有効化
- [x] 最大pacing rate
- [x] Path MTU Discovery
- [x] PMTUD probe数
- [x] HyStart
- [x] 最大送受信UDP payload size
- [x] ACK delay設定
- [x] send capacity factor

## P2: モバイルネットワーク

- [ ] QUIC connection migration
- [ ] Wi-Fiとモバイル回線切り替えの検知
- [ ] path validation
- [ ] Unity app suspend/resume時の接続管理
- [ ] バックグラウンド移行時のタイマー停止・再開
- [ ] ローカルアドレス変更時の再接続方針

## P2: 診断・可観測性

- [ ] EventSourceまたは同等のmanaged診断API
- [x] qlog出力（同期zero-copy UTF-8 handler、接続ID付きJSONレコード）
- [ ] TLS key log（Debugビルド限定）
- [ ] quicheログレベル設定
- [ ] 接続IDとリクエストIDの相関
- [x] connection pool統計
- [ ] 以下の接続統計を公開する
  - handshake時間
  - RTT
  - congestion window
  - bytes in flight
  - lost/retransmitted packet数
  - 使用中ストリーム数
  - 接続再利用回数
  - QPACK統計
- [ ] Unity Profiler markerを追加する

## P2: API・互換性

- [ ] `WorkerThreads`のグローバル設定とhandler単位設定を整理する
- [x] `HttpRequestMessage.Version`と`VersionPolicy`の扱いを定義する
- [x] HTTP/3必須モードとHTTP/2/1.1フォールバック方針を定義する
- [ ] proxy対応方針を決める
  - CONNECT-UDP/MASQUEを含む
- [ ] Unix Domain SocketはHTTP/3では直接対応できないことをAPI上で明確化する
- [ ] public APIへXML documentationを追加する

## テスト

- [x] HTTP/3対応ローカルテストサーバーを用意する
- [ ] GET/HEAD/POST/PUTと大容量body
- [ ] 双方向ストリーミング
- [ ] 同一接続上の多重化
- [ ] 大量並列要求
- [ ] response backpressure
- [ ] request backpressure
- [ ] 各段階でのキャンセル競合
- [x] GOAWAY
- [x] RESET_STREAM/STOP_SENDING
- [ ] packet loss・遅延・並べ替え
- [ ] IPv4/IPv6切り替え
- [ ] 証明書期限切れ・ホスト名不一致・不明CA
- [ ] カスタムCA・mTLS・DER pin・SPKI pin
- [ ] handler/responseの繰り返し生成・破棄
- [ ] 長時間接続とメモリリーク
- [ ] Unity実機でのIL2CPP callback競合

## 現在実装済み

- [x] quiche/tokio-quicheによるHTTP/3
- [x] オリジン単位の接続再利用
- [x] 単一接続上のリクエスト多重化
- [x] リクエスト・レスポンスのストリーミング
- [x] bounded channelと`System.IO.Pipelines`によるbackpressure
- [x] csbindgenによるFFI生成
- [x] Unity IL2CPP向けcallback保持
- [x] iOS `__Internal`切り替え
- [x] OSルートCAと組み込みMozilla CA
- [x] カスタムルートCA
- [x] mTLS
- [x] SNI/証明書名上書き
- [x] カスタム証明書検証
- [x] leaf証明書DER SHA-256ピンニング
- [x] `netstandard2.1`、`net10.0`、`net11.0`
