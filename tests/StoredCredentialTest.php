<?php

declare(strict_types=1);

namespace SilverStripe\WebAuthn\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Environment;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\MFA\Model\RegisteredMethod;
use SilverStripe\MFA\Store\SessionStore;
use SilverStripe\Security\Member;
use SilverStripe\WebAuthn\RegisterHandler;
use SilverStripe\WebAuthn\VerifyHandler;

/**
 * End to end through the real handlers and webauthn-lib, no mocks: register a software security key,
 * store the result as silverstripe/mfa does (RegisteredMethodManager: json_encode of the result context),
 * then log in with it.
 *
 * The fixtures in tests/fixtures/ were produced by this test (testWriteFixtures) under
 * web-auth/webauthn-lib 4.9.3. They are the data real sites hold today, so they must keep verifying
 * after any change of webauthn-lib: otherwise members lose their second factor on upgrade.
 */
class StoredCredentialTest extends SapphireTest
{
    protected $usesDatabase = true;

    private const HOST = 'example.test';
    private const ORIGIN = 'https://example.test';
    private const MEMBER_ID = 4242;

    protected function setUp(): void
    {
        parent::setUp();
        Director::config()->set('alternate_base_url', self::ORIGIN . '/');
        // RegisterHandler and VerifyHandler read the host from a PSR-7 request built from the globals
        $_SERVER['HTTP_HOST'] = self::HOST;
        $_SERVER['HTTPS'] = 'on';
        $_SERVER['SERVER_PORT'] = 443;
    }

    public static function formatProvider(): array
    {
        return [
            'none' => [SoftwareAuthenticator::FORMAT_NONE],
            'fido-u2f' => [SoftwareAuthenticator::FORMAT_FIDO_U2F],
        ];
    }

    #[DataProvider('formatProvider')]
    public function testRegisterThenVerify(string $format): void
    {
        $member = $this->createMember();
        $key = new SoftwareAuthenticator();
        $data = $this->register($member, $key, $format);

        $result = $this->verify($member, $data, $key);
        $this->assertTrue($result->isSuccessful(), 'First login: ' . $result->getMessage());
        $result = $this->verify($member, $data, $key);
        $this->assertTrue($result->isSuccessful(), 'Second login, higher counter: ' . $result->getMessage());
    }

    /**
     * A site can set authenticator_attachment to null (allow platform and cross-platform keys);
     * webauthn-lib 5 rejects an empty string there, so null must reach it as null.
     */
    #[DataProvider('formatProvider')]
    public function testRegisterThenVerifyWithoutAttachmentPreference(string $format): void
    {
        RegisterHandler::config()->set('authenticator_attachment', null);
        $member = $this->createMember();
        $key = new SoftwareAuthenticator();
        $data = $this->register($member, $key, $format);

        $result = $this->verify($member, $data, $key);
        $this->assertTrue($result->isSuccessful(), 'Login: ' . $result->getMessage());
    }

    /**
     * Badly typed fields make webauthn-lib 5's strict denormalizers throw a TypeError (not an Exception). With
     * webauthn-lib 4 that was a failed result; it must stay one rather than becoming an uncaught error.
     */
    public function testBadlyTypedInputGivesFailedResult(): void
    {
        $member = $this->createMember();
        $key = new SoftwareAuthenticator();

        // registration: transports must be a list
        $handler = Injector::inst()->create(RegisterHandler::class);
        $store = new SessionStore($member);
        $keyData = json_decode(json_encode($handler->start($store)), true)['keyData'];
        $credential = json_decode(base64_decode(
            $key->createCredential($keyData, self::ORIGIN, SoftwareAuthenticator::FORMAT_NONE)
        ), true);
        $credential['response']['transports'] = 'usb';
        $request = new HTTPRequest('POST', '/', [], [], json_encode(['credentials' => base64_encode(json_encode(
            $credential
        ))]));
        $this->assertFalse($handler->register($request, $store)->isSuccessful());

        // login: userHandle must be a string
        $data = $this->register($member, $key, SoftwareAuthenticator::FORMAT_NONE);
        $method = RegisteredMethod::create(['Data' => $data, 'MemberID' => $member->ID]);
        $handler = Injector::inst()->create(VerifyHandler::class);
        $store = new SessionStore($member);
        $publicKey = json_decode(json_encode($handler->start($store, $method)), true)['publicKey'];
        $assertion = json_decode(base64_decode(
            $key->getAssertion($publicKey, self::ORIGIN, self::HOST, (string) $member->ID)
        ), true);
        $assertion['response']['userHandle'] = 123;
        $request = new HTTPRequest('POST', '/', [], [], json_encode(['credentials' => base64_encode(json_encode(
            $assertion
        ))]));
        $this->assertFalse($handler->verify($request, $store, $method)->isSuccessful());
    }

    #[DataProvider('formatProvider')]
    public function testVerifyFailsWithWrongKey(string $format): void
    {
        $member = $this->createMember();
        $key = new SoftwareAuthenticator();
        $data = $this->register($member, $key, $format);

        // Same credential ID, different private key: the signature must not verify
        $impostor = new SoftwareAuthenticator(null, $key->getCredentialId());
        $result = $this->verify($member, $data, $impostor);
        $this->assertFalse($result->isSuccessful());
        $this->assertStringContainsStringIgnoringCase('signature', $result->getMessage());
    }

    /**
     * A registration stored by an earlier webauthn-lib version (see fixtures/README.md) must still verify.
     */
    #[DataProvider('formatProvider')]
    public function testStoredFixtureVerifies(string $format): void
    {
        $fixture = json_decode(
            file_get_contents(__DIR__ . '/fixtures/stored-credential-' . $format . '.json'),
            true
        );
        $member = $this->createMember((int) $fixture['memberID']);
        $key = new SoftwareAuthenticator(
            $fixture['privateKeyPem'],
            base64_decode($fixture['credentialId']),
            (int) $fixture['signCount']
        );

        $result = $this->verify($member, $fixture['data'], $key);
        $this->assertTrue($result->isSuccessful(), $result->getMessage());
    }

    /**
     * Writes the fixtures; runs only with WEBAUTHN_WRITE_FIXTURES=1 (once, under the webauthn-lib version
     * that real stored data comes from). Not part of a normal run.
     */
    public function testWriteFixtures(): void
    {
        if (!Environment::getEnv('WEBAUTHN_WRITE_FIXTURES')) {
            $this->markTestSkipped('Set WEBAUTHN_WRITE_FIXTURES=1 to (re)write tests/fixtures/');
        }
        $libVersion = \Composer\InstalledVersions::getPrettyVersion('web-auth/webauthn-lib');
        $moduleVersion = \Composer\InstalledVersions::getPrettyVersion('silverstripe/webauthn-authenticator');
        foreach ([SoftwareAuthenticator::FORMAT_NONE, SoftwareAuthenticator::FORMAT_FIDO_U2F] as $format) {
            $member = $this->createMember();
            $key = new SoftwareAuthenticator();
            $data = $this->register($member, $key, $format);
            // one login, so the fixture has seen a counter update as well
            $this->assertTrue($this->verify($member, $data, $key)->isSuccessful());
            file_put_contents(__DIR__ . '/fixtures/stored-credential-' . $format . '.json', json_encode([
                'createdWith' => 'web-auth/webauthn-lib ' . $libVersion
                    . ', silverstripe/webauthn-authenticator ' . $moduleVersion,
                'format' => $format,
                'memberID' => self::MEMBER_ID,
                'rpId' => self::HOST,
                'credentialId' => base64_encode($key->getCredentialId()),
                'signCount' => $key->getSignCount(),
                // test-only key of a software authenticator, not a secret
                'privateKeyPem' => $key->getPrivateKeyPem(),
                'data' => $data,
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        }
    }

    private function createMember(int $id = self::MEMBER_ID): Member
    {
        $member = Member::create(['FirstName' => 'Key', 'Surname' => 'Holder', 'Email' => 'key@example.test']);
        $member->ID = $id;
        // force an insert with this ID: the stored user handle is the member ID
        $member->write(false, true);
        return $member;
    }

    /**
     * @return string RegisteredMethod.Data as silverstripe/mfa stores it
     */
    private function register(Member $member, SoftwareAuthenticator $key, string $format): string
    {
        # via the Injector, which also sets the handler's logger dependency
        $handler = Injector::inst()->create(RegisterHandler::class);
        $store = new SessionStore($member);
        // what the browser receives: the JSON of start()
        $keyData = json_decode(json_encode($handler->start($store)), true)['keyData'];
        // a site's Director::host() is a bare host, for which the module sends no rp.id (browser default)
        $this->assertSame(self::HOST, $keyData['rp']['id'] ?? self::HOST);

        $request = new HTTPRequest('POST', '/', [], [], json_encode([
            'credentials' => $key->createCredential($keyData, self::ORIGIN, $format),
        ]));
        $result = $handler->register($request, $store);
        $this->assertTrue($result->isSuccessful(), 'Registration: ' . $result->getMessage());

        return json_encode($result->getContext());
    }

    private function verify(Member $member, string $data, SoftwareAuthenticator $key)
    {
        $method = RegisteredMethod::create(['Data' => $data, 'MemberID' => $member->ID]);
        $handler = Injector::inst()->create(VerifyHandler::class);
        $store = new SessionStore($member);
        $publicKey = json_decode(json_encode($handler->start($store, $method)), true)['publicKey'];

        $request = new HTTPRequest('POST', '/', [], [], json_encode([
            'credentials' => $key->getAssertion($publicKey, self::ORIGIN, self::HOST, (string) $member->ID),
        ]));
        return $handler->verify($request, $store, $method);
    }
}
