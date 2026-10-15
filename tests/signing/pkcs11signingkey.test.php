<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\test\signing;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use fyrkat\openssl\CSR;
use fyrkat\openssl\DN;
use fyrkat\openssl\OpenSSLConfig;
use fyrkat\openssl\OpenSSLKey;
use fyrkat\openssl\PrivateKey;
use fyrkat\openssl\X509;
use letswifi\error\UserException;
use letswifi\signing\OpenSSLCli;
use letswifi\signing\Pkcs11SigningKey;

/**
 * Integration test against a PKCS#11 software token (SoftHSM2).
 *
 * Skipped when SoftHSM2 or the OpenSSL pkcs11 provider is unavailable; on
 * the development VM these run against a throwaway token created per test.
 * The PIN below only protects that ephemeral test token.
 */
class Pkcs11SigningKeyTest extends TestCase
{
	private const TOKEN_LABEL = 'letswifi-test';

	private const KEY_LABEL = 'test-ca-key';

	private const PIN = '87654321';

	private const SO_PIN = '12345678';

	private ?string $workDir = null;

	private ?string $previousSofthsmConf = null;

	protected function setUp(): void
	{
		$module = $this->findSofthsmModule();
		if ( null === $module ) {
			$this->markTestSkipped( 'SoftHSM2 module not available' );
		}
		if ( !$this->hasPkcs11Provider() ) {
			$this->markTestSkipped( 'OpenSSL pkcs11 provider not available' );
		}
		if ( false === \shell_exec( 'command -v softhsm2-util' ) ) {
			$this->markTestSkipped( 'softhsm2-util not available' );
		}

		$this->workDir = \sys_get_temp_dir() . '/lwtest-' . \bin2hex( \random_bytes( 6 ) );
		$this->assertNotFalse( \mkdir( "{$this->workDir}/tokens", 0o700, true ) );
		\file_put_contents( "{$this->workDir}/softhsm2.conf", "directories.tokendir = {$this->workDir}/tokens\nobjectstore.backend = file\nlog.level = ERROR\n" );
		$this->previousSofthsmConf = \getenv( 'SOFTHSM2_CONF' ) ?: null;
		\putenv( "SOFTHSM2_CONF={$this->workDir}/softhsm2.conf" );

		$this->shell( 'softhsm2-util --init-token --free --label ' . self::TOKEN_LABEL . ' --pin ' . self::PIN . ' --so-pin ' . self::SO_PIN );

		// Software CA: key + self-signed certificate; only the key goes into the token
		$this->shell( 'openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out ' . \escapeshellarg( "{$this->workDir}/ca.key.pem" ) );
		$this->shell( 'openssl pkey -in ' . \escapeshellarg( "{$this->workDir}/ca.key.pem" ) . ' -outform der -out ' . \escapeshellarg( "{$this->workDir}/ca.key.der" ) );
		$this->shell( 'openssl req -x509 -new -key ' . \escapeshellarg( "{$this->workDir}/ca.key.pem" )
			. ' -subj /CN=SoftHSM\\ Test\\ CA -days 1 -addext basicConstraints=critical,CA:TRUE'
			. ' -out ' . \escapeshellarg( "{$this->workDir}/ca.pem" ) );
		$this->shell( 'softhsm2-util --import ' . \escapeshellarg( "{$this->workDir}/ca.key.der" )
			. ' --token ' . self::TOKEN_LABEL . ' --label ' . self::KEY_LABEL . ' --id aa --pin ' . self::PIN );
	}

	protected function tearDown(): void
	{
		if ( null !== $this->previousSofthsmConf ) {
			\putenv( "SOFTHSM2_CONF={$this->previousSofthsmConf}" );
		} else {
			\putenv( 'SOFTHSM2_CONF' );
		}
		if ( null !== $this->workDir ) {
			$this->shell( 'rm -r ' . \escapeshellarg( $this->workDir ) );
		}
	}

	public function testSignWithToken(): void
	{
		$caPem = (string)\file_get_contents( "{$this->workDir}/ca.pem" );
		$signingKey = new Pkcs11SigningKey(
			new OpenSSLCli(),
			new X509( $caPem ),
			'pkcs11:token=' . self::TOKEN_LABEL . ';object=' . self::KEY_LABEL . ';type=private',
			self::PIN,
			(string)$this->findSofthsmModule(),
		);

		$userKey = new PrivateKey( new OpenSSLConfig( privateKeyType: OpenSSLKey::KEYTYPE_EC ) );
		$clientCsr = CSR::generate( new DN( ['CN' => 'token-client'] ), $userKey );

		$userCert = $signingKey->sign(
			$clientCsr->getCSRPem(),
			new DN( ['CN' => 'signed-by-token@example.com'] ),
			"basicConstraints = CA:FALSE\nextendedKeyUsage = clientAuth\n",
			9876,
			new DateTimeImmutable( '-1 hour' ),
			new DateTimeImmutable( '+24 hours' ),
		);

		$this->assertStringContainsString( 'signed-by-token@example.com', (string)$userCert->getSubject() );
		$this->assertTrue( $userCert->isSignedBy( new X509( $caPem ) ) );
	}

	public function testFailsClosedOnWrongPin(): void
	{
		$caPem = (string)\file_get_contents( "{$this->workDir}/ca.pem" );
		$signingKey = new Pkcs11SigningKey(
			new OpenSSLCli(),
			new X509( $caPem ),
			'pkcs11:token=' . self::TOKEN_LABEL . ';object=' . self::KEY_LABEL . ';type=private',
			'00000000',
			(string)$this->findSofthsmModule(),
		);

		$userKey = new PrivateKey( new OpenSSLConfig( privateKeyType: OpenSSLKey::KEYTYPE_EC ) );
		$clientCsr = CSR::generate( new DN( ['CN' => 'token-client'] ), $userKey );

		$this->expectException( UserException::class );
		$this->expectExceptionMessageMatches( '/command failed/' );
		$signingKey->sign(
			$clientCsr->getCSRPem(),
			new DN( ['CN' => 'nope@example.com'] ),
			'basicConstraints = CA:FALSE',
			9877,
			new DateTimeImmutable( '-1 hour' ),
			new DateTimeImmutable( '+24 hours' ),
		);
	}

	private function findSofthsmModule(): ?string
	{
		foreach ( [
			'/usr/lib/softhsm/libsofthsm2.so',
			'/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so',
			'/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so',
			'/usr/local/lib/softhsm/libsofthsm2.so',
			'/opt/homebrew/lib/softhsm/libsofthsm2.so',
		] as $path ) {
			if ( \file_exists( $path ) ) {
				return $path;
			}
		}

		return null;
	}

	private function hasPkcs11Provider(): bool
	{
		\exec( 'openssl list -providers -provider default -provider pkcs11 2>/dev/null', $output, $exitCode );

		return 0 === $exitCode;
	}

	/**
	 * @param non-empty-string $command
	 */
	private function shell( string $command ): void
	{
		$output = [];
		$exitCode = 1;
		\exec( $command . ' 2>&1', $output, $exitCode );
		$this->assertSame( 0, $exitCode, $command . ' failed: ' . \implode( "\n", $output ) );
	}
}
