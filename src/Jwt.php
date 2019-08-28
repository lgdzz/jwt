<?php

namespace lgdz;

use \Exception;

class Jwt extends Rsa
{

    private $signatureAlg = 'SHA256';

    public function __construct(string $privateKey, string $publicKey)
    {
        if ($publicKey = openssl_get_publickey($publicKey)) {
            $this->publicKey = $publicKey;
        } else {
            throw new Exception('openssl public_key_id error');
        }

        if ($privateKey = openssl_get_privatekey($privateKey)) {
            $this->privateKey = $privateKey;
        } else {
            throw new Exception('openssl private_key_id error');
        }
    }

    /**
     * @param array $data
     * @param int $expire
     * @return string
     * @throws Exception
     */
    public function issue(array $data, int $expire): string
    {
        $header = ['typ' => 'JWT', 'alg' => $this->signatureAlg];
        $payload = array_merge(['exp' => time() + $expire], $data);
        $jwt = [];
        $jwt[] = $this->urlsafeB64encode(json_encode($header));
        $jwt[] = $this->urlsafeB64encode($this->privateEncrypt(json_encode($payload)));
        $jwt[] = $this->urlsafeB64encode($this->sign(implode('.', $jwt), $this->privateKey));
        return implode('.', $jwt);
    }

    /**
     * @param string $token
     * @return array
     * @throws Exception
     */
    public function check(string $token): array
    {
        $jwt = explode('.', $token);
        if (count($jwt) !== 3) {
            throw new Exception('token format error');
        }

        list($headerB64, $payloadB64, $signatrueB64) = $jwt;
        $header = $this->urlsafeB64decode($headerB64);
        $payload = $this->urlsafeB64decode($payloadB64);
        $signatrue = $this->urlsafeB64decode($signatrueB64);

        //check signature
        $checkSignParams = ["{$headerB64}.{$payloadB64}", $signatrue, $this->publicKey];
        $checkSignResult = $this->verifySign(...$checkSignParams);
        if (!$checkSignResult) {
            throw new Exception('signature error');
        }

        $payload = json_decode($this->publicDecrypt($payload), true);

        //check expire
        if ($payload['exp'] < time()) {
            throw new Exception('token invalid');
        }

        unset($payload['exp']);
        return $payload;
    }

    private function sign(string $data, $privateKey): string
    {
        $signature = '';
        if (!openssl_sign($data, $signature, $privateKey, $this->signatureAlg)) {
            throw new Exception('openssl sign fail');
        } else {
            return $signature;
        }
    }

    private function verifySign(string $data, string $signature, $publicKey): int
    {
        return openssl_verify($data, $signature, $publicKey, $this->signatureAlg);
    }
}