<?php

use PHPUnit\Framework\TestCase;

use JWT\Token;

class TokenTest extends TestCase
{

	public function testMakeValidate()
    {
        $token = Token::make([
        	'key' => 'secret',
        	'issuer' => 'artisangang',
        	'expiry' => strtotime('+1 hour'),
        	'issuedAt' => time(),
        	'algorithm' => 'HS256'
        ])->get();


        $this->assertEquals(Token::validate($token, 'secret'), [
        	'issuer' => 'artisangang',
        	'expiry' => strtotime('+1 hour'),
        	'issuedAt' => time()
        ]);
    }

    public function testMakeCheck()
    {
        $token = Token::make([
        	'key' => 'secret',
        	'issuer' => 'artisangang',
        	'expiry' => strtotime('+1 hour'),
        	'issuedAt' => time(),
        	'algorithm' => 'HS256'
        ])->get();


        $this->assertEquals(Token::check($token, 'secret'), true);

         $token = Token::make([
        	'key' => 'secret',
        	'issuer' => 'artisangang',
        	'expiry' => strtotime('-1 hour'),
        	'issuedAt' => time(),
        	'algorithm' => 'HS256'
        ])->get();


        $this->assertEquals(Token::check($token, 'secret'), false);

         $token = Token::make([
        	'key' => 'secret',
        	'issuer' => 'artisangang',
        	'expiry' => strtotime('-1 hour'),
        	'issuedAt' => time(),
        	'algorithm' => 'HS256'
        ])->get();


        $this->assertEquals(Token::check($token, 'invalid'), false);

    }

    /**
     * @expectedException JWT\Exceptions\TokenExpiredException
     */
    public function testExpiredToken()
    {
        
        $payload = [
        	'key' => 'secret',
            'issuer' => "abc",
            'issuedAt' => time(),
            "expiry" => time() - 20
        ];

        $token = Token::make($payload)->get();
        
        Token::validate($token, 'secret');
    }

    /**
     * @expectedException DomainException
     */
    public function testMalformed()
    {
        $token = Token::make([
        	'key' => 'secret',
        	'issuer' => pack('c', 128),
        	'expiry' => strtotime('-1 hour'),
        	'issuedAt' => time(),
        	'algorithm' => 'HS256'
        ])->get();
    }

    /**
     * @expectedException DomainException
     */
    public function testMalformedDecode()
    {
 
        (new Token)->decodeSegment(base64_encode('i m invalid.'));
    }

    /**
     * @expectedException DomainException
     */
    public function testMalformedEncode()
    {
 
        (new Token)->encodeSegment([pack('c', 128)]);
    }

    /**
     * @expectedException JWT\Exceptions\BeforeValidException
     */
    public function testUsedBeforeValid()
    {
    	 $payload = [
        	'key' => 'secret',
            'issuer' => "abc",
            'issuedAt' => time(),
            "expiry" => time() + 60,
            'NotBefore' => time() + 10
        ];

        $token = Token::make($payload)->get();
        
        Token::validate($token, 'secret');
    }

    public function testTokenBeforeValid()
    {
    	 $payload = [
        	'key' => 'secret',
            'issuer' => "abc",
            'issuedAt' => time(),
            "expiry" => time() + 60,
            'NotBefore' => time() - 10
        ];

        $token = Token::make($payload)->get();      
  

        $this->assertEquals(Token::check($token, 'invalid'), false);
    }

     /**
     * @expectedException JWT\Exceptions\BeforeValidException
     */
    public function testUsedBeforeIssuedAt()
    {
    	 $payload = [
        	'key' => 'secret',
            'issuer' => "abc",
            'issuedAt' => time() + 10,
            "expiry" => time() + 60,
        ];

        $token = Token::make($payload)->get();
        
        Token::validate($token, 'secret');
    }

    public function testRSMakeVerify()
    {

    	$res = openssl_pkey_new(array('digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA));

    	openssl_pkey_export($res, $privKey);

    	$token = Token::make([
        	'key' => $privKey,
        	'issuer' => 'artisangang',
        	'expiry' => strtotime('+1 hour'),
        	'issuedAt' => time(),
        	'algorithm' => 'RS256'
        ])->get();

    	$pubKey = openssl_pkey_get_details($res);
        $pubKey = $pubKey['key'];

        $this->assertEquals(Token::validate($token, $pubKey), [
        	'issuer' => 'artisangang',
        	'expiry' => strtotime('+1 hour'),
        	'issuedAt' => time()
        ]);
    }

     /**
     * @expectedException UnexpectedValueException
     */
    public function testInvalidSegment()
    {
        Token::decode('header.body', 'secret');
    }

    public function testBreakToken()
    {

        $expiry = strtotime('+1 hour');
        $time = time();

        $token = Token::make([
            'key' => 'your_secret_key',
            'issuer' => 'world_open_source_development',
            'expiry' => $expiry,
            'issuedAt' => $time
        ]);

     
        $tokenStr = $token->get();

        $token = Token::break($tokenStr, 'your_secret_key');

        $this->assertInstanceOf(Token::class, $token);

        
        $reflector = new \ReflectionClass($token);
        $reflector_property = $reflector->getProperty('claims');
        $reflector_property->setAccessible(true);

        $data = $reflector_property->getValue($token);


        $this->assertEquals('world_open_source_development', $data['iss']);
        $this->assertEquals($expiry, $data['exp']);

       
    }

}