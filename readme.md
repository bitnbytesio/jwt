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


Using methods

```php

$token = new Token;

$token->setKey('secret);

$token->setIssuer('who issued this token');

$token->setSubject('subject of token');

$token->setAudience('recipients');

// of in case of multiple audience
//$token->setAudience('recipient1', 'recipient2', 'recipient3');

// this will work with unix timestamp
$token->setExpiry(time() + 60);

// this token cannot be used before
$token->setNotBefore(time() + 10);

// token issued at unix time stamp
// Note: token cannot be used before issued at time
$token->setIssuedAt(time());

$token->setIdentity('this must be unique');

$token->setType('jwt');

// suported algorithm: HS256,HS512,HS384
// for oppen ssl : RS256,RS384,RS512 
$token->setAlgorithm('HS256');

// add custom claims to token
$token->setClaim('user_id', 1);
$token->setClaim('email', 'user@example.com');

// generate token based on claims
$tokenString = $token->get();



```

Validating a token

```php

// use one from below methods

try {
    
    // this will return array of claims
    $token = Token::validate('token string', 'your key');
    
    // you may validate custom claims here
    
   } catch(\Exception $e) 
   {
        //InvalidArgumentException -> some required argument is missing
        //UnexpectedValueException -> argument or segment value is malformed
        //InvalidSignatureException -> token signature not matched , Token is invalid
        //BeforeValidException -> token is used before issued at or not before time
        //TokenExpiredException -> token is expired
   }
   
// or by using check, this will return bool

if (!Token::check('token string', 'your key'))
{
    // token is not valid
}

```

For more information explorer JWT\Token.php.

Use openssl_pkcs12_read,openssl_get_privatekey to read key.
