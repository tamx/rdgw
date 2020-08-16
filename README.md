# rdgw

rdgw は Microsoft の Remote Desktop Protocol を中継する Gateway サーバーです。

## 使い方

~~~
% rdgw [username] [password]
~~~

と実行することにより、 13389番ポートで待ち受けます。
このとき、 gateway のユーザー名は username 、パスワードは password になります。

私的に使用するために開発したので、１ユーザーしか受け付けません。
認証方法は NTLMv2, Digest（未確認）, Basic に対応しています。

## 注意

単独では SSL でカプセルしません。通常は SSL 接続で利用すると思いますので、 stone などを併用して下さい。

[centrifuge](https://github.com/tamx/centrifuge) でも以下のようにして利用できます。

~~~
% centrifuge -p :443/ssl localhost:80 RDG:localhost:13389
~~~
