# Stored credential fixtures

`stored-credential-none.json` and `stored-credential-fido-u2f.json` hold `RegisteredMethod.Data` exactly as a site stores it today, one per attestation format the module registers (`none`, `fido-u2f`). They were written by `StoredCredentialTest::testWriteFixtures` with web-auth/webauthn-lib 4.9.3 and the unchanged module source of tag 5.3.3 (`createdWith` shows the name of the working branch, whose `src/` was still identical to 5.3.3 at that point).

Each one is a real registration made by `SoftwareAuthenticator` (a software security key with an ES256 key pair) through the real `RegisterHandler`, followed by one login through the real `VerifyHandler`. `privateKeyPem` is that software key's private key, so a test can sign new logins with it. It is test data, not a secret.

`StoredCredentialTest::testStoredFixtureVerifies` must keep passing after any change of webauthn-lib. If it fails, registrations stored on live sites would stop working and members would lose their second factor. Do not regenerate these files to make that test pass. They are meant to stay as written by webauthn-lib 4.
