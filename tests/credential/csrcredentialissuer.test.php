<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\test\credential;

use DateInterval;
use DateTimeImmutable;
use PDO;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionProperty;
use fyrkat\configmap\DictionaryRaw;
use fyrkat\multilang\MultiLanguageString;
use fyrkat\openssl\CSR;
use fyrkat\openssl\DN;
use fyrkat\openssl\OpenSSLConfig;
use fyrkat\openssl\OpenSSLKey;
use fyrkat\openssl\PrivateKey;
use fyrkat\openssl\X509;
use letswifi\auth\AuthenticationContext;
use letswifi\auth\User;
use letswifi\credential\CsrCredentialIssuer;
use letswifi\credential\CsrValidator;
use letswifi\error\UserException;
use letswifi\profile\NetworkSSID;
use letswifi\profile\ProfileService;
use letswifi\profile\Provider;
use letswifi\profile\Realm;
use letswifi\signing\OpenSSLCli;

/**
 * End-to-end test of the CSR enrollment issuer with a software CA key and an
 * in-memory SQLite logging database; no token involved.
 */
class CsrCredentialIssuerTest extends TestCase
{
	private const CA_SUBJECT = 'CN=CSR Test CA';

	private const REALM = 'test.example.org';

	private PDO $pdo;

	private ProfileService $profileService;

	private CsrCredentialIssuer $issuer;

	private string $clientCsrPem;

	protected function setUp(): void
	{
		// A new in-memory SQLite database is needed per test (shared
		// connections persist for the whole process only while referenced).
		$this->pdo = new PDO( 'sqlite::memory:' );
		$this->pdo->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
		$this->pdo->exec( <<<SQL
			CREATE TABLE "realm_signing_log" (
				"serial" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
				"realm" TEXT NOT NULL,
				"ca_sub" TEXT NOT NULL,
				"requester" TEXT NOT NULL,
				"sub" TEXT NOT NULL,
				"grant" TEXT DEFAULT NULL,
				"ident" TEXT NOT NULL,
				"issued" TEXT NOT NULL,
				"expires" TEXT NOT NULL,
				"csr" TEXT NOT NULL,
				"x509" TEXT,
				"revoked" TEXT,
				"usage" TEXT NOT NULL,
				"source" TEXT NOT NULL DEFAULT 'server_generated',
				"client" TEXT,
				"user_agent" TEXT,
				"ip" TEXT
			)
			SQL );

		[$this->profileService, $this->issuer] = $this->buildFixtures();

		$clientKey = new PrivateKey( new OpenSSLConfig( privateKeyType: OpenSSLKey::KEYTYPE_EC ) );
		$this->clientCsrPem = CSR::generate(
			new DN( ['CN' => 'client-asked-for-this'] ),
			$clientKey,
		)->getCSRPem();
	}

	public function testIssueFromCsr(): void
	{
		$validator = new CsrValidator( new OpenSSLCli() );
		$csrPem = $validator->validate( $this->clientCsrPem );

		$credential = $this->issuer->issueFromCsr( $csrPem );

		// Identity comes from server config, not from the CSR subject
		$payload = $credential->getPayload();
		$cert = new X509( $payload['x509'] );
		$subject = (string)$cert->getSubject();
		$this->assertStringContainsString( '@' . \rawurlencode( self::REALM ), $subject );
		$this->assertStringNotContainsString( 'client-asked-for-this', $subject );

		// No private key may be present in the response
		$this->assertStringNotContainsString( 'PRIVATE KEY', $payload['x509'] );
		$this->assertNotEmpty( $payload['chain'] );
		$this->assertStringContainsString( 'BEGIN CERTIFICATE', $payload['chain'][0] );

		// The certificate must verify against the CA
		$caCert = $this->profileService->getCertificate( self::CA_SUBJECT );
		$this->assertTrue( $cert->isSignedBy( $caCert ) );

		// The issuance must be logged as a client certificate with source "csr",
		// together with the final certificate
		$row = $this->pdo->query( 'SELECT * FROM "realm_signing_log"' )->fetch( PDO::FETCH_ASSOC );
		$this->assertNotFalse( $row );
		$this->assertSame( CsrCredentialIssuer::USAGE, $row['usage'] );
		$this->assertSame( CsrCredentialIssuer::SOURCE, $row['source'] );
		$this->assertSame( self::REALM, $row['realm'] );
		$this->assertSame( 'tester', $row['requester'] );
		$this->assertSame( $credential->credentialId, $row['ident'] );
		$this->assertStringContainsString( 'BEGIN CERTIFICATE', (string)$row['x509'] );
	}

	public function testIssuanceLimit(): void
	{
		$realm = $this->getProperty( $this->issuer, 'realm' );
		// Set a limit of 1 via realm extra on a re-constructed issuer
		$limitedRealm = new Realm(
			profileService: $this->profileService,
			realmId: $realm->realmId,
			displayName: new MultiLanguageString( ['en' => 'Test'] ),
			serverNames: ['radius.test.example.org'],
			trust: [self::CA_SUBJECT],
			signer: self::CA_SUBJECT,
			validity: $realm->validity,
			networks: $realm->networks,
			extra: ['csr_issuance_limit' => '1'],
		);
		$issuer = new CsrCredentialIssuer(
			$this->getProperty( $this->issuer, 'user' ),
			$limitedRealm,
			new DateTimeImmutable(),
			$this->profileService,
		);

		$issuer->issueFromCsr( $this->clientCsrPem );
		$this->expectException( UserException::class );
		$this->expectExceptionMessage( 'issuance_limit_reached: Issuance limit reached' );
		$this->expectExceptionCode( 429 );
		$issuer->issueFromCsr( $this->clientCsrPem );
	}

	public function testFailedIssuanceRowDoesNotConsumeQuota(): void
	{
		$realm = $this->getProperty( $this->issuer, 'realm' );
		$limitedRealm = new Realm(
			profileService: $this->profileService,
			realmId: $realm->realmId,
			displayName: new MultiLanguageString( ['en' => 'Test'] ),
			serverNames: ['radius.test.example.org'],
			trust: [self::CA_SUBJECT],
			signer: self::CA_SUBJECT,
			validity: $realm->validity,
			networks: $realm->networks,
			extra: ['csr_issuance_limit' => '2'],
		);
		$issuer = new CsrCredentialIssuer(
			$this->getProperty( $this->issuer, 'user' ),
			$limitedRealm,
			new DateTimeImmutable(),
			$this->profileService,
		);

		$issuer->issueFromCsr( $this->clientCsrPem );

		// Simulate the audit row of a failed signing attempt: prepared row,
		// never completed (x509 NULL). It must not count against the quota.
		$statement = $this->pdo->prepare( <<<SQL
			INSERT INTO "realm_signing_log"
				("realm", "ca_sub", "requester", "sub", "ident", "issued", "expires", "csr", "usage", "source")
			VALUES
				(:realm, :ca_sub, 'tester', :sub, 'orphan@test', :issued, :expires, :csr, 'client', 'csr')
			SQL );
		$statement->execute( [
			'realm' => self::REALM,
			'ca_sub' => self::CA_SUBJECT,
			'sub' => 'CN=orphan@test',
			'issued' => \gmdate( 'Y-m-d H:i:s' ),
			'expires' => \gmdate( 'Y-m-d H:i:s', \time() + 86400 ),
			'csr' => $this->clientCsrPem,
		] );

		// Second completed issuance: allowed because the orphan is excluded
		$issuer->issueFromCsr( $this->clientCsrPem );

		$this->expectException( UserException::class );
		$this->expectExceptionCode( 429 );
		$issuer->issueFromCsr( $this->clientCsrPem );
	}

	/**
	 * @return array{ProfileService,CsrCredentialIssuer}
	 */
	private function buildFixtures(): array
	{
		$caKey = new PrivateKey( new OpenSSLConfig( privateKeyType: OpenSSLKey::KEYTYPE_EC ) );
		$caDn = new DN( ['CN' => 'CSR Test CA'] );
		$caCert = CSR::generate( $caDn, $caKey )->sign(
			null,
			$caKey,
			new DateTimeImmutable( '+1 year' ),
			new OpenSSLConfig( x509Extensions: OpenSSLConfig::X509_EXTENSION_CA ),
			1,
		);

		$config = new DictionaryRaw( [
			'certificate' => [
				self::CA_SUBJECT => ['x509' => $caCert->getX509Pem(), 'key' => $caKey->getPrivateKeyPem( null )],
			],
		] );

		$profileService = new ProfileService( $config, 'portal.test.example.org' );
		// Point the service's lazy PDO at our prepared test database
		$reflection = new ReflectionProperty( ProfileService::class, 'pdo' );
		$reflection->setValue( $profileService, $this->pdo );

		$realm = new Realm(
			profileService: $profileService,
			realmId: self::REALM,
			displayName: new MultiLanguageString( ['en' => 'Test realm'] ),
			serverNames: ['radius.test.example.org'],
			trust: [self::CA_SUBJECT],
			signer: self::CA_SUBJECT,
			validity: new DateInterval( 'P1D' ),
			networks: [new NetworkSSID( 'eduroam', new MultiLanguageString( ['en' => 'eduroam'] ), 'eduroam' )],
		);

		// The credential issuer never touches authentication, so the provider's
		// auth context can remain an uninitialized stub.
		$auth = ( new ReflectionClass( AuthenticationContext::class ) )->newInstanceWithoutConstructor();
		$provider = new Provider(
			tenantConfig: $profileService,
			host: 'portal.test.example.org',
			displayName: new MultiLanguageString( ['en' => 'Test'] ),
			auth: $auth,
			realmAccess: ['' => [self::REALM]],
		);

		$user = new User(
			userId: 'tester',
			provider: $provider,
			realms: [self::REALM => $realm],
			affiliations: [],
			clientId: 'test',
			grantSid: null,
			ip: '127.0.0.1',
			userAgent: 'phpunit',
		);

		return [
			$profileService,
			new CsrCredentialIssuer( $user, $realm, new DateTimeImmutable(), $profileService ),
		];
	}

	/**
	 * @template T
	 *
	 * @param class-string<T> $name
	 *
	 * @return T
	 */
	private function getProperty( object $object, string $name ): mixed
	{
		$property = new ReflectionProperty( $object, $name );

		return $property->getValue( $object );
	}
}
