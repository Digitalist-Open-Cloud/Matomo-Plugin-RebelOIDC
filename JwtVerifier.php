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
 * Verifies RS256-signed JWTs against a JWKS. Pure PHP + openssl, no Matomo
 * dependencies. Audience/authorized-party checks are left to the caller.
 */
class JwtVerifier
{
    /** @var callable */
    private $jwksFetch;

    /**
     * @param callable $jwksFetch function (bool $forceRefresh): array  returning ['keys' => [...]]
     */
    public function __construct(callable $jwksFetch)
    {
        $this->jwksFetch = $jwksFetch;
    }

    /**
     * The id token must be issued for this client: `aud` (string or list) contains $clientId.
     *
     * @throws InvalidTokenException
     */
    public static function assertAudience(array $payload, string $clientId): void
    {
        $aud = $payload['aud'] ?? null;
        $auds = is_array($aud) ? $aud : [$aud];
        if ($clientId === '' || !in_array($clientId, $auds, true)) {
            throw new InvalidTokenException('audience does not contain the client id');
        }
    }

    /**
     * OIDC Core 5.3.2: the userinfo `sub` MUST equal the `sub` of the verified id token.
     *
     * @throws InvalidTokenException
     */
    public static function assertSameSubject(array $verifiedIdToken, array $userinfo): void
    {
        $idSub = $verifiedIdToken['sub'] ?? null;
        $infoSub = $userinfo['sub'] ?? null;
        if (!is_string($idSub) || $idSub === '' || !is_string($infoSub) || $infoSub !== $idSub) {
            throw new InvalidTokenException('userinfo subject does not match the id token subject');
        }
    }

    /**
     * The access token must have been issued to this client: `azp` equals $clientId.
     *
     * @throws InvalidTokenException
     */
    public static function assertAuthorizedParty(array $payload, string $clientId): void
    {
        if ($clientId === '' || ($payload['azp'] ?? null) !== $clientId) {
            throw new InvalidTokenException('authorized party is not the client id');
        }
    }

    /**
     * Decide whether an access token is a JWS issued by our IdP and must therefore be
     * verified (and its claims used). Anything else (opaque string, JWE, JWS from another
     * issuer) is treated as opaque: only usable as a bearer, no claims are read from it.
     * A JWS that claims our issuer is always verified, so a bad signature fails the login.
     */
    public static function shouldVerifyAccessToken(string $token, string $issuer): bool
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3 || $parts[0] === '' || $parts[1] === '' || $parts[2] === '') {
            return false;
        }
        try {
            $header = json_decode(self::base64UrlDecode($parts[0]), true);
            $payload = json_decode(self::base64UrlDecode($parts[1]), true);
        } catch (InvalidTokenException $e) {
            return false;
        }
        if (!is_array($header) || !is_string($header['alg'] ?? null) || !is_array($payload)) {
            return false;
        }
        return $issuer !== '' && ($payload['iss'] ?? null) === $issuer;
    }

    /**
     * Legacy mode only: the payload claims of a JWS WITHOUT any verification, as plugin
     * versions before 5.2.0 did. Anything that is not a decodable JWS (opaque token, JWE,
     * garbage) contributes no claims instead of throwing. Never use this for trust decisions
     * in verification mode.
     *
     * @return array The unverified payload claims, empty when the token is not a JWS.
     */
    public static function unverifiedClaims(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3 || $parts[1] === '') {
            return [];
        }
        try {
            $payload = json_decode(self::base64UrlDecode($parts[1]), true);
        } catch (InvalidTokenException $e) {
            return [];
        }
        return is_array($payload) ? $payload : [];
    }

    /**
     * @return array The verified payload claims.
     * @throws InvalidTokenException
     */
    public function verify(string $jwt, string $issuer, int $now, int $leeway = 60): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3 || $parts[0] === '' || $parts[1] === '' || $parts[2] === '') {
            throw new InvalidTokenException('Malformed token: expected three non-empty parts');
        }

        $header = $this->decodeJson($parts[0], 'header');
        $payload = $this->decodeJson($parts[1], 'payload');
        $signature = $this->decodeSegment($parts[2], 'signature');

        if (($header['alg'] ?? null) !== 'RS256') {
            throw new InvalidTokenException('Unsupported token algorithm, only RS256 is accepted');
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            throw new InvalidTokenException('Token header has no kid');
        }

        $jwk = $this->findKey($kid);
        if ($jwk === null) {
            $jwk = $this->findKey($kid, true);
        }
        if ($jwk === null) {
            throw new InvalidTokenException('No signing key found for kid ' . $this->printable($kid));
        }

        $pem = $this->jwkToPem($jwk);
        $result = openssl_verify($parts[0] . '.' . $parts[1], $signature, $pem, OPENSSL_ALGO_SHA256);
        if ($result !== 1) {
            throw new InvalidTokenException('Invalid token signature');
        }

        if (!isset($payload['iss']) || !is_string($payload['iss']) || $payload['iss'] !== $issuer) {
            throw new InvalidTokenException('Token issuer does not match');
        }
        if (!isset($payload['exp']) || !is_numeric($payload['exp'])) {
            throw new InvalidTokenException('Token has no exp claim');
        }
        if ($now > $payload['exp'] + $leeway) {
            throw new InvalidTokenException('Token has expired');
        }
        if (isset($payload['nbf']) && (!is_numeric($payload['nbf']) || $now < $payload['nbf'] - $leeway)) {
            throw new InvalidTokenException('Token is not yet valid (nbf)');
        }
        if (isset($payload['iat']) && (!is_numeric($payload['iat']) || $now < $payload['iat'] - $leeway)) {
            throw new InvalidTokenException('Token issued in the future (iat)');
        }

        return $payload;
    }

    public static function base64UrlDecode(string $s): string
    {
        $decoded = base64_decode(strtr($s, '-_', '+/'), true);
        if ($decoded === false) {
            throw new InvalidTokenException('Invalid base64url encoding');
        }
        return $decoded;
    }

    private function decodeSegment(string $segment, string $what): string
    {
        try {
            return self::base64UrlDecode($segment);
        } catch (InvalidTokenException $e) {
            throw new InvalidTokenException("Malformed token $what: invalid base64url");
        }
    }

    private function decodeJson(string $segment, string $what): array
    {
        $data = json_decode($this->decodeSegment($segment, $what), true);
        if (!is_array($data)) {
            throw new InvalidTokenException("Malformed token $what: invalid JSON");
        }
        return $data;
    }

    private function findKey(string $kid, bool $forceRefresh = false): ?array
    {
        try {
            $jwks = ($this->jwksFetch)($forceRefresh);
        } catch (\Throwable $e) {
            throw new InvalidTokenException('Could not fetch JWKS: ' . $e->getMessage());
        }
        if (!is_array($jwks) || !isset($jwks['keys']) || !is_array($jwks['keys'])) {
            throw new InvalidTokenException('Invalid JWKS document');
        }
        foreach ($jwks['keys'] as $key) {
            if (
                is_array($key)
                && ($key['kid'] ?? null) === $kid
                && ($key['kty'] ?? null) === 'RSA'
                && (!isset($key['use']) || $key['use'] === 'sig')
                && is_string($key['n'] ?? null)
                && is_string($key['e'] ?? null)
            ) {
                return $key;
            }
        }
        return null;
    }

    private function jwkToPem(array $jwk): string
    {
        $n = self::base64UrlDecode($jwk['n']);
        $e = self::base64UrlDecode($jwk['e']);

        $rsaPublicKey = $this->asn1(0x30, $this->asn1Integer($n) . $this->asn1Integer($e));
        // rsaEncryption OID 1.2.840.113549.1.1.1 followed by NULL
        $algorithm = $this->asn1(0x30, "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00");
        $spki = $this->asn1(0x30, $algorithm . $this->asn1(0x03, "\x00" . $rsaPublicKey));

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private function asn1Integer(string $bytes): string
    {
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '' || (ord($bytes[0]) & 0x80)) {
            $bytes = "\x00" . $bytes;
        }
        return $this->asn1(0x02, $bytes);
    }

    private function asn1(int $tag, string $content): string
    {
        $len = strlen($content);
        if ($len < 0x80) {
            $lenBytes = chr($len);
        } else {
            $lenBytes = ltrim(pack('N', $len), "\x00");
            $lenBytes = chr(0x80 | strlen($lenBytes)) . $lenBytes;
        }
        return chr($tag) . $lenBytes . $content;
    }

    private function printable(string $s): string
    {
        return substr(preg_replace('/[^\x20-\x7e]/', '?', $s), 0, 64);
    }
}
