package main

import (
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func main() {

	// JWT 生成.
	token, err := jwt.NewBuilder().
		Issuer("hyuga.tsukui").
		Subject("6a1ba3c4-9a96-40b4-beed-e9c2f8927124").
		Expiration(time.Now().Add(2*time.Hour)).
		Claim("name", "tsukui").
		Claim("email", "john.doe@example.com").Build()
	if err != nil {
		log.Fatal(err)
	}

	// ファイルから秘密鍵を読み込む.
	f, err := os.Open("sample_pem")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	rowKey, err := io.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(rowKey)
	if block == nil {
		log.Fatalf("Failed to parse PEM block containing the key.")
		return
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse private key: %s", err)
		return
	}

	// JWT 署名.
	serialized, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, privKey))
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(serialized))

	// JWT 検証.
	// ファイルから公開鍵を読み込む.
	f, err = os.Open("sample_pem.pub")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	rowKey, err = io.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}

	// 公開鍵を JWK に変換.
	key, err := jwk.ParseKey(rowKey, jwk.WithPEM(true))
	if err != nil {
		log.Fatal(err)
	}

	// JWT 検証.
	token, err = jwt.Parse(serialized, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		log.Fatal(err)
	}
	log.Println(token)
}
