# RFC 9421 HTTP Message Signatures 用 Java ライブラリ

## ライセンス

  Apache License, Version 2.0

## Maven

```xml
<dependency>
    <groupId>com.authlete</groupId>
    <artifactId>http-message-signatures</artifactId>
    <version>${http-message-signatures.version}</version>
</dependency>
```

最新バージョンを知るには [CHANGES.md](CHANGES.md) ファイルを確認してください。

## ソースコード

  <code>https://github.com/authlete/http-message-signatures</code>

## JavaDoc

  <code>https://authlete.github.io/http-message-signatures</code>

## 標準仕様

以下は、HTTPメッセージ署名に関連する標準仕様の一覧です（網羅的なものではありません）。

### IETF RFC

- [RFC 8941][RFC_8941] Structured Field Values for HTTP
- [RFC 9421][RFC_9421] HTTP Message Signatures

### IANA Assignments

- IANA: [HTTP Message Signature][IANA_HTTP_MESSAGE_SIGNATURE]

### OpenID

- [FAPI 2.0 Http Signatures][FAPI_20_HTTP_SIGNATURES]

## 概要

HTTP メッセージ署名生成時の大まかな手順は次の通りです。

1. Signature Base を作成する。
2. Signature Base に対する署名を作成する。
3. 署名を `Signature` HTTP フィールドに入れる。
4. 署名のメタデータを `Signature-Input` HTTP フィールドに入れる。

HTTP メッセージ署名検証時の大まかな手順は次の通りです。

1. `Signature` HTTP フィールドから署名を取り出す。
2. `Signature-Input` HTTP フィールドから署名のメタデータを取り出す。
3. Signature Base を作成する。
4. 署名が、Signature Base に対して有効か検証する。

## 詳細

### Signature Base 作成

`SignatureBase` クラスが Signature Base を表します。

`SignatureBaseBuilder` クラスは `SignatureBase` クラスのインスタンスを作成するためのユーティリティです。
`SignatureBaseBuilder` クラスは、入力として `SignatureContext` インターフェースの実装インスタンスと
`SignatureMetadata` クラスのインスタンスを必要とします。

`SignatureContext` インターフェースは、指定されたコンポーネント識別子に対応する値を返却する下記のメソッドを一つだけ持つインターフェースです。

```java
String getComponentValue(
        SignatureMetadata metadata, ComponentIdentifier identifier) throws SignatureException;
```

下記のコードは、派生コンポーネント (derived component) `@method` の値だけを返すことができる
`SignatureContext` インターフェース実装例です。

```java
public class Context implements SignatureContext
{
    // "@method" を表すコンポーネント識別子
    private static final ComponentIdentifier COMP_ID_METHOD = new ComponentIdentifier("@method");

    @Override
    String getComponentValue(
            SignatureMetadata metadata, ComponentIdentifier identifier) throws SignatureException
    {
        // "@method"
        if (identifier.equals(COMP_ID_METHOD))
        {
            return "GET";
        }

        return null;
    }
}
```

`SignatureMetadata` クラスは、署名の対象となるコンポーネント群とパラメータ群のリストを表現します。
下記のコードは、`@method` だけを含む `SignatureMetadata` インスタンスの生成例です。

```java
List<ComponentIdentifier> identifiers = Arrays.asList(
        new ComponentIdentifier("@method")
);

SignatureMetadata metadata = new SignatureMetadata(identifiers);
```

`SignatureContext` と `SignatureMetadata` のインスタンスを用いて、次のように
`SignatureBase` インスタンを作成することができます。

```java
SignatureBase base = new SignatureBaseBuilder(context).build(metadata);
```

### 署名

`SignatureBase` クラスの `sign(HttpSigner)` メソッドを呼ぶことで署名を生成できます。

```java
public byte[] sign(HttpSigner signer) throws SignatureException
```

`SignatureBase` クラスの `sign` メソッドの引数である `HttpSigner` は、シリアライズされた
Signature Base を入力として受け取り署名を返す、下記のメソッドを一つだけ持つインターフェースです。

```java
byte[] sign(byte[] signatureBase) throws SignatureException;
```

このライブラリに含まれている `HttpSigner` インターフェースの実装である `JoseHttpSigner`
クラスを用いると、署名処理は次のように記述することができます。

```java
JWK signingKey = ...;

byte[] signature = base.sign(new JoseHttpSigner(signingKey));
```

TBW

## コンタクト

Authlete コンタクトフォーム: https://www.authlete.com/ja/contact/

<!-- ==================== LINKS ==================== -->

[RFC_8941]: https://www.rfc-editor.org/rfc/rfc8941.html
[RFC_9421]: https://www.rfc-editor.org/rfc/rfc9421.html

[IANA_HTTP_MESSAGE_SIGNATURE]: https://www.iana.org/assignments/http-message-signature/http-message-signature.xhtml

[FAPI_20_HTTP_SIGNATURES]: https://openid.bitbucket.io/fapi/fapi-2_0-http-signatures.html
