<?php

declare(strict_types=1);

namespace SilverStripe\WebAuthn\Tests;

use RuntimeException;
use SilverStripe\Dev\TestOnly;

/**
 * A minimal software security key for tests: real ES256 (P-256) keys, real CBOR, real signatures.
 *
 * The handler tests mock webauthn-lib entirely, so they cannot show that registrations stored by one
 * webauthn-lib version still verify under another. This class produces the same requests a browser
 * sends (see client/src/lib/auth.js), so a test can run the real RegisterHandler and VerifyHandler
 * end to end, with no mocks, and keep the stored RegisteredMethod data as a fixture.
 */
class SoftwareAuthenticator implements TestOnly
{
    /**
     * Attestation formats the module registers (BaseHandlerTrait::getAttestationStatementSupportManager()).
     */
    public const FORMAT_NONE = 'none';
    public const FORMAT_FIDO_U2F = 'fido-u2f';

    /** @var string PEM of the credential private key */
    private string $privateKeyPem;

    private string $credentialId;

    private int $signCount;

    /**
     * @param string|null $privateKeyPem Existing credential key (a fixture), or null to generate one
     * @param string|null $credentialId Raw credential ID that goes with the key
     * @param int $signCount Signature counter the next assertion starts from
     */
    public function __construct(?string $privateKeyPem = null, ?string $credentialId = null, int $signCount = 0)
    {
        $this->privateKeyPem = $privateKeyPem ?? self::newEcKeyPem();
        $this->credentialId = $credentialId ?? random_bytes(32);
        $this->signCount = $signCount;
    }

    public function getPrivateKeyPem(): string
    {
        return $this->privateKeyPem;
    }

    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    /**
     * Answer a registration challenge like navigator.credentials.create() plus client/src/lib/auth.js do.
     *
     * @param array $keyData The decoded JSON "keyData" that RegisterHandler::start() sends to the browser
     * @param string $origin e.g. https://example.test
     * @param string $format One of the FORMAT_* constants
     * @return string The value the client posts as "credentials"
     */
    public function createCredential(array $keyData, string $origin, string $format): string
    {
        $clientDataJson = json_encode([
            'type' => 'webauthn.create',
            'challenge' => self::base64UrlEncode(self::base64AnyDecode($keyData['challenge'])),
            'origin' => $origin,
            'crossOrigin' => false,
        ], JSON_UNESCAPED_SLASHES);
        // without rp.id the browser uses the origin's host (the module sends none when Director::host() is bare)
        $rpIdHash = hash('sha256', $keyData['rp']['id'] ?? parse_url($origin, PHP_URL_HOST), true);

        // fido-u2f keys carry no AAGUID, so it must be all zeroes for that format
        $aaguid = $format === self::FORMAT_FIDO_U2F ? str_repeat("\0", 16) : random_bytes(16);
        [$x, $y] = $this->publicKeyCoordinates();
        $coseKey = self::cbor([1 => 2, 3 => -7, -1 => 1, -2 => self::bytes($x), -3 => self::bytes($y)]);

        // flags: UP (0x01) + AT (0x40); then counter, attested credential data
        $authData = $rpIdHash . chr(0x41) . pack('N', $this->signCount)
            . $aaguid . pack('n', strlen($this->credentialId)) . $this->credentialId . $coseKey;

        if ($format === self::FORMAT_NONE) {
            $attStmt = [];
        } elseif ($format === self::FORMAT_FIDO_U2F) {
            // U2F attestation: separate attestation key + self-signed certificate (x5c)
            $attestationKeyPem = self::newEcKeyPem();
            $certDer = self::selfSignedCertDer($attestationKeyPem);
            $signed = "\x00" . $rpIdHash . hash('sha256', $clientDataJson, true)
                . $this->credentialId . "\x04" . $x . $y;
            $attStmt = [
                'sig' => self::bytes(self::sign($signed, $attestationKeyPem)),
                'x5c' => [self::bytes($certDer)],
            ];
        } else {
            throw new RuntimeException('Unsupported format ' . $format);
        }

        $attestationObject = self::cbor([
            'fmt' => $format,
            'attStmt' => $attStmt,
            'authData' => self::bytes($authData),
        ]);

        return base64_encode(json_encode([
            'id' => self::base64UrlEncode($this->credentialId),
            'type' => 'public-key',
            'rawId' => self::clientBase64($this->credentialId),
            'response' => [
                'clientDataJSON' => self::clientBase64($clientDataJson),
                'attestationObject' => self::clientBase64($attestationObject),
            ],
        ], JSON_UNESCAPED_SLASHES));
    }

    /**
     * Answer a login challenge like navigator.credentials.get() plus client/src/lib/auth.js do.
     *
     * @param array $publicKey The decoded JSON "publicKey" that VerifyHandler::start() sends to the browser
     * @param string $origin e.g. https://example.test
     * @param string $rpId The relying party ID (host) the credential was registered for
     * @param string $userHandle Raw user handle (the member ID)
     * @return string The value the client posts as "credentials"
     */
    public function getAssertion(array $publicKey, string $origin, string $rpId, string $userHandle): string
    {
        $this->signCount++;
        $clientDataJson = json_encode([
            'type' => 'webauthn.get',
            'challenge' => self::base64UrlEncode(self::base64AnyDecode($publicKey['challenge'])),
            'origin' => $origin,
            'crossOrigin' => false,
        ], JSON_UNESCAPED_SLASHES);
        // flags: UP (0x01) only
        $authData = hash('sha256', $rpId, true) . chr(0x01) . pack('N', $this->signCount);
        $signature = self::sign($authData . hash('sha256', $clientDataJson, true), $this->privateKeyPem);

        return base64_encode(json_encode([
            'id' => self::base64UrlEncode($this->credentialId),
            'type' => 'public-key',
            'rawId' => self::clientBase64($this->credentialId),
            'response' => [
                'clientDataJSON' => self::clientBase64($clientDataJson),
                'authenticatorData' => self::clientBase64($authData),
                'signature' => self::clientBase64($signature),
                'userHandle' => self::clientBase64($userHandle),
            ],
        ], JSON_UNESCAPED_SLASHES));
    }

    /**
     * @return string[] Raw 32-byte x and y of the credential public key
     */
    private function publicKeyCoordinates(): array
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_private($this->privateKeyPem));
        return [
            str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT),
            str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT),
        ];
    }

    private static function newEcKeyPem(): string
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        openssl_pkey_export($key, $pem);
        return $pem;
    }

    private static function selfSignedCertDer(string $keyPem): string
    {
        $key = openssl_pkey_get_private($keyPem);
        $csr = openssl_csr_new(['commonName' => 'Test U2F Attestation'], $key, ['digest_alg' => 'sha256']);
        $cert = openssl_csr_sign($csr, null, $key, 365, ['digest_alg' => 'sha256']);
        openssl_x509_export($cert, $pem);
        // PEM body is the base64 of the DER
        return base64_decode(preg_replace('/-----[^-]+-----|\s/', '', $pem));
    }

    /**
     * ES256 signature in the DER form WebAuthn uses
     */
    private static function sign(string $data, string $keyPem): string
    {
        if (!openssl_sign($data, $signature, openssl_pkey_get_private($keyPem), OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Signing failed');
        }
        return $signature;
    }

    /**
     * client/src/lib/convert.js byteArrayToBase64(): standard base64 with the padding stripped
     */
    private static function clientBase64(string $raw): string
    {
        return rtrim(base64_encode($raw), '=');
    }

    private static function base64UrlEncode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * client/src/lib/convert.js base64ToByteArray(): accepts standard and URL-safe base64
     */
    public static function base64AnyDecode(string $encoded): string
    {
        return base64_decode(strtr($encoded, '-_', '+/'));
    }

    /**
     * Marks a string as a CBOR byte string (anything else that is a string encodes as text)
     */
    private static function bytes(string $raw): object
    {
        return (object) ['bytes' => $raw];
    }

    /**
     * Minimal CBOR encoder: unsigned/negative ints, byte and text strings, arrays and maps
     */
    private static function cbor($value): string
    {
        if (is_object($value)) {
            return self::cborHead(2, strlen($value->bytes)) . $value->bytes;
        }
        if (is_int($value)) {
            return $value >= 0 ? self::cborHead(0, $value) : self::cborHead(1, -1 - $value);
        }
        if (is_string($value)) {
            return self::cborHead(3, strlen($value)) . $value;
        }
        if (is_array($value)) {
            if ($value === [] || array_keys($value) !== range(0, count($value) - 1)) {
                $out = self::cborHead(5, count($value));
                foreach ($value as $k => $v) {
                    $out .= self::cbor($k) . self::cbor($v);
                }
                return $out;
            }
            $out = self::cborHead(4, count($value));
            foreach ($value as $v) {
                $out .= self::cbor($v);
            }
            return $out;
        }
        throw new RuntimeException('Cannot CBOR-encode ' . gettype($value));
    }

    private static function cborHead(int $major, int $length): string
    {
        $m = $major << 5;
        if ($length < 24) {
            return chr($m | $length);
        }
        if ($length < 0x100) {
            return chr($m | 24) . chr($length);
        }
        if ($length < 0x10000) {
            return chr($m | 25) . pack('n', $length);
        }
        return chr($m | 26) . pack('N', $length);
    }
}
