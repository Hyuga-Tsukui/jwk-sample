# "github.com/lestrrat-go/jwx"の検証

## ユースケースメモ
PEM形式で保存されているファイルを利用したJWTの検証を試したい.
AWS Cognito & ALBを利用した認証で生成されるJWTはPEM形式で配布される公開鍵で検証する必要があるため.