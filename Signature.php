<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */

namespace Piwik\Plugins\RebelOIDC;

/**
 * Checks the signature of a JWT against the keys the provider publishes.
 */
class Signature
{
    private const RSA_DIGESTS = [
        'RS256' => OPENSSL_ALGO_SHA256,
        'RS384' => OPENSSL_ALGO_SHA384,
        'RS512' => OPENSSL_ALGO_SHA512,
    ];

    /**
     * The start of a public key on the curve P-256, up to the point itself.
     */
    private const P256_KEY_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    /**
     * Whether one of the keys signed the token. RS256, RS384, RS512 and ES256 are supported: a
     * token that says it is signed in another way, or not at all, is not valid.
     *
     * @param array<string, mixed> $jwks the key set of the provider
     */
    public static function isValid(
        #[\SensitiveParameter]
        string $jwt,
        array $jwks
    ): bool {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return false;
        }

        $header = json_decode((string) self::decode($parts[0]), true);
        $signature = self::decode($parts[2]);
        $algorithm = is_array($header) ? ($header['alg'] ?? null) : null;
        if (!is_string($algorithm) || $signature === null) {
            return false;
        }

        if (isset(self::RSA_DIGESTS[$algorithm])) {
            $keyType = 'RSA';
            $digest = self::RSA_DIGESTS[$algorithm];
        } elseif ($algorithm === 'ES256' && strlen($signature) === 64) {
            $keyType = 'EC';
            $digest = OPENSSL_ALGO_SHA256;
            // OpenSSL wants the two numbers of the signature as a sequence.
            $signature = self::asn1(0x30, self::asn1Integer(substr($signature, 0, 32)) . self::asn1Integer(substr($signature, 32)));
        } else {
            return false;
        }

        foreach ((array) ($jwks['keys'] ?? []) as $key) {
            $isCandidate = is_array($key)
                && ($key['kty'] ?? null) === $keyType
                && (!isset($key['use']) || $key['use'] === 'sig')
                && (!isset($header['kid']) || ($key['kid'] ?? null) === $header['kid']);
            if (!$isCandidate) {
                continue;
            }

            $pem = $keyType === 'RSA' ? self::rsaKeyToPem($key) : self::ecKeyToPem($key);
            $publicKey = $pem === null ? false : openssl_pkey_get_public($pem);
            if ($publicKey !== false && openssl_verify($parts[0] . '.' . $parts[1], $signature, $publicKey, $digest) === 1) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $key
     */
    private static function rsaKeyToPem(array $key): ?string
    {
        $modulus = is_string($key['n'] ?? null) ? self::decode($key['n']) : null;
        $exponent = is_string($key['e'] ?? null) ? self::decode($key['e']) : null;
        if ($modulus === null || $exponent === null) {
            return null;
        }

        $rsaKey = self::asn1(0x30, self::asn1Integer($modulus) . self::asn1Integer($exponent));
        // The object identifier of RSA encryption, followed by NULL.
        $algorithm = self::asn1(0x30, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00");

        return self::pem(self::asn1(0x30, $algorithm . self::asn1(0x03, "\x00" . $rsaKey)));
    }

    /**
     * @param array<string, mixed> $key
     */
    private static function ecKeyToPem(array $key): ?string
    {
        $x = is_string($key['x'] ?? null) ? self::decode($key['x']) : null;
        $y = is_string($key['y'] ?? null) ? self::decode($key['y']) : null;
        if (($key['crv'] ?? null) !== 'P-256' || $x === null || $y === null || strlen($x) !== 32 || strlen($y) !== 32) {
            return null;
        }

        return self::pem(hex2bin(self::P256_KEY_PREFIX) . "\x04" . $x . $y);
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function asn1Integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        // A first bit that is set would make the number negative.
        if ($bytes === '' || (ord($bytes[0]) & 0x80)) {
            $bytes = "\x00" . $bytes;
        }

        return self::asn1(0x02, $bytes);
    }

    private static function asn1(int $tag, string $content): string
    {
        $length = strlen($content);
        if ($length < 0x80) {
            return chr($tag) . chr($length) . $content;
        }

        $lengthBytes = ltrim(pack('N', $length), "\x00");

        return chr($tag) . chr(0x80 | strlen($lengthBytes)) . $lengthBytes . $content;
    }

    private static function decode(string $base64Url): ?string
    {
        $decoded = base64_decode(strtr($base64Url, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }
}
