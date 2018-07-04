PHP-JWT
=======

PHP7 library for JSON Web Tokens (JWT).

[Standard]https://en.wikipedia.org/wiki/JSON_Web_Token#Standard_fields

Installation
------------

```sh
composer require artisangang/jwt
```

Requires PHP 7.

Usage
-----

```php
<?php


// create token

$token = Token::make([
    	'key' => 'secret',
    	'issuer' => 'artisangang',
    	'expiry' => strtotime('+1 hour'),
    	'issuedAt' => time(),
    	'algorithm' => 'HS256'
    ])->get();


try {
	Token::validate($token, 'secret');
} catch (\Exception $e) {
	//InvalidArgumentException|UnexpectedValueException
	//InvalidSignatureException|BeforeValidException|TokenExpiredException
}

/**
 * or
 * Token::check($token, 'secret')
 * this will return true or false only
 */

//  decode token
// (new Token)->decode('token', 'key')

// token string to token object
// Token::break('token', 'key')

// jwt claims maping with Token Class
/**
 * [
 *    'iss' => 'issuer',
 *    'sub' => 'subject',
 *    'aud' => 'audience',
 *    'exp' => 'expiry',
 *    'nbf' => 'notBefore',
 *    'iat' => 'issuedAt',
 *    'jti' => 'identify',
 *    'typ' => 'type',
 *    'alg' => 'algorithm'
 *]
 */

```

Use openssl_pkcs12_read,openssl_get_privatekey to read key.