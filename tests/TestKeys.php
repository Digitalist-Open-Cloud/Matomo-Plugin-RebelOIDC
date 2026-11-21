<?php

namespace Piwik\Plugins\RebelOIDC\tests;

/**
 * Keys of a provider in a test, and tokens signed with them.
 */
class TestKeys
{
    /**
     * @return \OpenSSLAsymmetricKey
     */
    public static function createRsaKey()
    {
        return openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    }

    /**
     * @return \OpenSSLAsymmetricKey
     */
    public static function createEcKey()
    {
        return openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
    }

    /**
     * The public key the way a provider publishes it.
     *
     * @param \OpenSSLAsymmetricKey $key
     * @return array<string, string>
     */
    public static function toJwk($key, string $kid): array
    {
        $details = openssl_pkey_get_details($key);
        if (isset($details['rsa'])) {
            return ['kty' => 'RSA', 'use' => 'sig', 'kid' => $kid, 'n' => self::encode($details['rsa']['n']), 'e' => self::encode($details['rsa']['e'])];
        }

        return [
            'kty' => 'EC',
            'use' => 'sig',
            'kid' => $kid,
            'crv' => 'P-256',
            'x' => self::encode(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)),
            'y' => self::encode(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT)),
        ];
    }

    /**
     * @param array<string, mixed> $header
     * @param array<string, mixed> $claims
     * @param \OpenSSLAsymmetricKey $key
     */
    public static function sign(array $header, array $claims, $key): string
    {
        $signed = self::encode(json_encode($header)) . '.' . self::encode(json_encode($claims));
        openssl_sign($signed, $signature, $key, OPENSSL_ALGO_SHA256);

        if (($header['alg'] ?? '') === 'ES256') {
            // OpenSSL gives the two numbers as a sequence, a JWT has them one after the other.
            $offset = 3;
            $numbers = '';
            foreach ([0, 1] as $ignored) {
                $length = ord($signature[$offset]);
                $numbers .= str_pad(ltrim(substr($signature, $offset + 1, $length), "\0"), 32, "\0", STR_PAD_LEFT);
                $offset += $length + 2;
            }
            $signature = $numbers;
        }

        return $signed . '.' . self::encode($signature);
    }

    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
