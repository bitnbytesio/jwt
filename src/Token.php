<?php

namespace JWT;

use JWT\Exceptions\{BeforeValidException, InvalidSignatureException, TokenExpiredException};

use InvalidArgumentException, UnexpectedValueException, DomainException, DateTime, RuntimeException;

class Token
{
 
    /**
     * supported algs
     * @var array
     */
    protected $supportedAlgs = array(
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'RS256' => array('openssl', 'SHA256'),
        'RS384' => array('openssl', 'SHA384'),
        'RS512' => array('openssl', 'SHA512'),
    );

    /**
     * custom claims
     * @var array
     */
    protected $claims = [];

    /**
     * header of token
     * @var array
     */
    protected $header = ['typ' => 'jwt', 'alg' => 'HS512'];

    /**
     * key to verify/sign token
     * @var string
     */
    protected $key = null;

    /**
     * properties map
     * @var array
     */
    protected $propertiesMap = [
        'iss' => 'issuer',
        'sub' => 'subject',
        'aud' => 'audience',
        'exp' => 'expiry',
        'nbf' => 'notBefore',
        'iat' => 'issuedAt',
        'jti' => 'identify',
        'typ' => 'type',
        'alg' => 'algorithm'
    ];
    
    /**
     * create token object
     * @param array|array $payload 
     * @return void
     */
    public function __construct(array $payload = [])
    {
        $this->setIssuedAt(time());
        $this->setExpiry(time() + 60 * 60);
        $this->load($payload);
    }

    /**
     * load full payload including headers
     * @param array $payload 
     * @return void
     */
    public function load(array $payload) : void
    {
         foreach ($payload as $key => $value) {

            $method = 'set'.ucfirst($key);

            if (is_callable([$this, $method])) {                
                call_user_func_array([$this, $method], [$value]);
            } else {
                $this->setClaim($key, $value);
            }
        }
    }
    
    /**
     * set key
     * @param string $key 
     * @return self
     */
    public function setKey(string $key) : self 
    {
        $this->key = $key;

        return $this;
    }

    /**
     * iss: Identifies principal that issued the JWT.
     * @param string $iss 
     * @return self
     */
    public function setIssuer(string $iss) : self
    {
        $this->claims['iss'] = $iss;

        return $this;
    }

    /**
     * sub: Identifies the subject of the JWT.
     * @param string $value 
     * @return self
     */
    public function setSubject(string $value) : self
    {
        $this->claims['sub'] = $value;
        
        return $this;

    }

    /**
     * aud: Identifies the recipients that the JWT is intended for. Each principal intended to 
     * process the JWT must identify itself with a value in the audience claim. If the principal
     *  processing the claim does not identify itself with a value in the aud claim when this
     *  claim is present, then the JWT must be rejected
     * @param string ...$value 
     * @return self
     */
    public function setAudience(string ...$value) : self
    {
        $this->claims['aud'] = $value;

        return $this;
    }

    /**
     * exp: Identifies the expiration time on or after which 
     * the JWT must not be accepted for processing.
     * @param int $time 
     * @return self
     */
    public function setExpiry(int $time) : self
    {
        $this->claims['exp'] = $time;

        return $this;
    }

    /**
     * nbf: Identifies the time on which the JWT will start to be accepted for processing.
     * @param int $time 
     * @return self
     */
    public function setNotBefore(int $time) : self
    {
        $this->claims['nbf'] = $time;

        return $this;
    }

    /**
     * iat: Identifies the time at which the JWT was issued.
     * @param int $time 
     * @return self
     */
    public function setIssuedAt(int $time) : self
    {
        $this->claims['iat'] = $time;

        return $this;
    }

    /**
     * jti: Case sensitive unique identifier of the token even among different issuers.
     * @param string $value 
     * @return self
     */
    public function setIdentity(string $value) : self
    {
        $this->claims['jti'] = $value;

        return $this;
    }

    /**
     * typ: If present, it is recommended to set this to JWT.
     * @param string $value 
     * @return self
     */
    public function setType(string $value) : self
    {   
        $this->header['typ'] = $value;

        return $this;
    }

    /**
     * alg: The issuer can freely set an algorithm to verify the signature on the token.
     * However, some supported algorithms are insecure
     * @param string $value 
     * @return self
     */
    public function setAlgorithm(string $value) : self
    {

        if (!isset($this->supportedAlgs[$value])) {
            throw new InvalidArgumentException("{$value} algorithm is not supported");
        }

        $this->header['alg'] = $value;

        return $this;
    }

    /**
     * set custom claims
     * @param string $name 
     * @param string $value 
     * @return self
     */
    public function setClaim(string $name, string $value) : self
    {
        $this->claims[$name] = $value;

        return $this;
    }

    /**
     * check if token if valid or not
     * @param string $token 
     * @param string $key 
     * @return bool
     */
    public static function check(string $token, string $key) : bool
    {

        try {

            $instance = new self;

            $instance->decode($token, $key);

            return true;

        } catch (\Exception $e)
        {

        }

        return false;

    }

    /**
     * validate token, instead of returing true/false this will return array of claims
     * @param string $token 
     * @param string $key 
     * @return array
     */
    public static function validate(string $token, string $key) : array
    {
        
        $instance = new self;       

        return $instance->remap( $instance->decode($token, $key)['payload'] );
        
    }

    /**
     * decode token
     * @param string $token 
     * @param string $key 
     * @return array
     */
    public function decode(string $token, string $key) : array
    {   

       
        $timestamp = time();

        if (empty($key)) {
            throw new InvalidArgumentException('Key may not be empty');
        }

        $tokenArray = explode('.', $token);

        if (count($tokenArray) != 3) {
            throw new UnexpectedValueException('Invalid token as number of segments are incorrent');
        }

        list($headerB64, $bodyB64, $signB64) = $tokenArray;

        
        if (null === ($header = $this->decodeSegment($headerB64))) {
            throw new UnexpectedValueException('Invalid header');
        }

        if (null === ($payload = $this->decodeSegment($bodyB64))) {
            throw new UnexpectedValueException('Invalid claims');
        }
        if (false === ($sig = $this->urlSafeDecoding($signB64))) {
            throw new UnexpectedValueException('Invalid signature');
        }
        if (empty($header->alg)) {
            throw new UnexpectedValueException('Algorithm missing');
        }
        if (empty($this->supportedAlgs[$header->alg])) {
            throw new UnexpectedValueException('Algorithm not supported');
        }
            
        

        if (!$this->verifySign("$headerB64.$bodyB64", $sig, $key, $header->alg)) {
            throw new InvalidSignatureException('Invalid signature');
        }
       

        if (isset($payload->nbf) && $payload->nbf > $timestamp) {
            throw new BeforeValidException(
                'Token may not be used prior to ' . date(DateTime::ISO8601, $payload->nbf)
            );
        }

        if ($payload->iat > $timestamp) {
            throw new BeforeValidException(
                'Token may not be used prior to ' . date(DateTime::ISO8601, $payload->iat)
            );
        }
       
              
        if ($timestamp >= $payload->exp) {
            throw new TokenExpiredException('Token may expired');
        }

        return ['header' => (array) $header, 'payload' => (array) $payload];
    }

    /**
     * remap payload/claims property as per assignment
     * @param array $payload 
     * @return array
     */
    public function remap(array $payload) : array
    {   
        
        foreach ($this->propertiesMap as $key => $label) {            
            if (isset($payload[$key])) {
                $payload[$label] = $payload[$key];
                unset($payload[$key]);
            }
        }

        return $payload;
    }

    /**
     * decode token segment
     * @param string $value 
     * @return stdClass
     */
    public function decodeSegment(string $value) : \stdClass
    {
        
        $value = $this->urlSafeDecoding($value);

        $obj = json_decode($value, false, 512, JSON_BIGINT_AS_STRING);


        if ($errno = json_last_error()) {
            $this->_handleJsonError($errno);
        } elseif ($obj === null && $value !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;


    }

    /**
     * encode token segment
     * @param array $value 
     * @return string
     */
    public function encodeSegment(array $value) : string
    {
        

        $json = json_encode($value);
        if ($errno = json_last_error()) {
            $this->_handleJsonError($errno);
        } elseif ($json === 'null' && $input !== null) {
            throw new DomainException('Null result with non-null input');
        }
        
        return $this->urlSafeEncoding($json);
    }

    /**
     * url safe encoding
     * @param string $value 
     * @return string
     */
    public function urlSafeEncoding(string $value) : string
    {
        return str_replace('=', '', strtr(base64_encode($value), '+/', '-_'));
    }

    /**
     * url safe decoding
     * @param string $value 
     * @return type
     */
    public function urlSafeDecoding(string $value) : string
    {
         if ($remainder = strlen($value) % 4) {
            $padlen = 4 - $remainder;
            $value .= str_repeat('=', $padlen);
        }

        return base64_decode(strtr($value, '-_', '+/'));
    }
    
    /**
     * generate token
     * @param array $payload 
     * @return self
     */
    public static function make(array $payload) : self
    {
        return new static($payload);                    
       
    }

    /**
     * re-construct token object from string
     * @param string $token 
     * @param string $key 
     * @return self
     */
    public static function break(string $token, string $key) : self
    {   


        $instance =  new static();
        $decoded = $instance->decode($token, $key);
        $instance->setKey($key);
        $instance->load( $instance->remap( array_merge($decoded['header'], $decoded['payload']) ) );

        return $instance;        

    }

    /**
     * create token
     * @return string
     */
    public function get() : string
    {


        $segments = [];
        $segments[] = $this->encodeSegment($this->header);
        $segments[] = $this->encodeSegment($this->claims);
        $signature = $this->sign(implode('.', $segments), $this->key, $this->header['alg']);
        $segments[] = $this->urlSafeEncoding($signature);
        return implode('.', $segments);
    }
   

    /**
     * sign token
     * @param string $context 
     * @param string $key 
     * @param string $alg 
     * @return string
     */
    public function sign(string $context, string $key, string $alg) : string
    {
        if (empty($this->supportedAlgs[$alg])) {
            throw new DomainException('Algorithm not supported');
        }
        list($function, $algorithm) = $this->supportedAlgs[$alg];
        switch($function) {
            case 'hash_hmac':
            default:
                return hash_hmac($algorithm, $context, $key, true);
            case 'openssl':
                $signature = '';
                $success = openssl_sign($context, $signature, $key, $algorithm);
                if (!$success) {
                    throw new DomainException("OpenSSL unable to sign context");
                } else {
                    return $signature;
                }
        }
    }
   
    /**
     * verify token signature
     * @param string $context 
     * @param string $signature 
     * @param string $key 
     * @param string $alg 
     * @return bool
     */
    public function verifySign(string $context, string $signature, string $key, string $alg) : bool
    {
        if (empty($this->supportedAlgs[$alg])) {
            throw new DomainException("Algorithm {$alg} not supported");
        }
        list($function, $algorithm) = $this->supportedAlgs[$alg];

        switch($function) {
            case 'openssl':
                $success = openssl_verify($context, $signature, $key, $algorithm);
                if ($success === 1) {
                    return true;
                } elseif ($success === 0) {
                    return false;
                }
                // returns 1 on success, 0 on failure, -1 on error.
                throw new DomainException(
                    'OpenSSL error: ' . openssl_error_string()
                );
            case 'hash_hmac':
            default:             
                return hash_equals($signature, hash_hmac($algorithm, $context, $key, true));
                             
        }
    }
    
    /**
     * handle json errors
     * @param int $errno 
     * @return void
     */
    private function _handleJsonError(int $errno) : void
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters'
        );
        throw new DomainException(
            isset($messages[$errno])
            ? $messages[$errno]
            : 'Unknown JSON error: ' . $errno
        );
    }
  
}