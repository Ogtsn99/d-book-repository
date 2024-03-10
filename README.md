# d-book-repository

実行方法

.envを作って以下を追加してください。このPRIVATE_KEYはhardhatのテスト用なので問題ないです
```
PRIVATE_KEY=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

## ACCを起動する
別リポジトリにある[AccessControlContract](https://github.com/Ogtsn99/AccessControlContract)で、以下のコマンドを時刻
```
$ hardhat node
// もう一つターミナルを開いて
$ npx hardhat run scripts/deploy.ts --network localhost
```
以上のコマンドが成功すればHardhat Network（仮想イーサリアムネットワーク）を起動して、
そこにACCをデプロイできているはず。

scripts/deploy.tsの中ではタイトルとマークルルートの登録処理も実行している。また、以下で立ち上げるノードの登録もここで行っている。

## d-book-repositoryを立ち上げる
現状40グループで各1台という設定にしている（変えるのはいろんな場所を触ることになって面倒くさいことになっている）

まずは以下のコマンドで1台立ち上げる
```
cargo run --release -- --listen-address /ip4/127.0.0.1/tcp/40837 --group 0 provide
```
--group 0はグループ0に属することを表し、provideはd-book-repositoryのストレージノードとして起動することを表している

次に、以下のコマンドで残りの39台を一気に立ち上げることができる
```
node set_providers.js
```

### d-book-repositoryにデータを保存する

以下のコマンドでファイルをアップロードできる。もしかすると/storageというディレクトリを作っておかなければ失敗するかもしれない。
（ノードが受け取ったシャードは/storage以下に保存されることになっている）
```
cargo run -- --peer /ip4/127.0.0.1/tcp/40837/p2p/12D3KooWCxnyz1JxC9y1RniRQVFe2cLaLHsYNc2SnXbM7yq5JBbJ --listen-address /ip4/127.0.0.1/tcp/45943 --secret-key-seed 199 upload --name 10MB_Sample
```

現状は1MB_Sample, 10MB_Sample, 100MB_Sampleのみアップロード可能。
これ以外のファイルをアップロードするにはACCのdeploy.tsの35行目あたりにタイトル名とマークルルートを事前に登録する処理があるので、
追加する。マークルルートは上のコマンドを違うファイルを指定してするとコンソールに出てくるはず。
例えば、10MB_SampleをCargo.tomlに変えてやると、マークルルート: 963cd1180ab4a8e79016c7d2176a19b8dce63e733dd82497c02c045142a53090が出力されるはず

### d-book-repositoryから書籍をDLする

/downloadというディレクトリを作っておいてください。そこにダウンロードしたデータが復元された状態で保存されます。

以下のコマンドで取得できます。このコマンドではACCのdeployに使用したアカウントで書籍を取ります。
```
cargo run -- --peer /ip4/127.0.0.1/tcp/40837/p2p/12D3KooWCxnyz1JxC9y1RniRQVFe2cLaLHsYNc2SnXbM7yq5JBbJ --listen-address /ip4/127.0.0.1/tcp/40942 --secret-key-seed 200 get --name 10MB_Sample
```

download以下に10MB_Sampleというファイルがあれば成功です。