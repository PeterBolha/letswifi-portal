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
 * Regression test for the argument position of -provider options.
 *
 * OpenSSL only accepts -provider as an option OF the subcommand; in front
 * of 'x509' it fails with "Invalid command '-provider'".  The actual
 * SoftHSM2 integration test (pkcs11signingkey.test.php) self-skips when no
 * PKCS#11 module is present, so this recording-CLI test guards the argv
 * layout on every run, without a token and without any cryptography.
 */
class ProviderArgsTest extends TestCase
{
	public function testProviderArgsComeAfterSubcommand(): void
	{
		$caKey = new PrivateKey( new OpenSSLConfig( privateKeyType: OpenSSLKey::KEYTYPE_EC ) );
		$caDn = new DN( ['CN' => 'Provider Args Test CA'] );
		$caCert = CSR::generate( $caDn, $caKey )->sign(
			null,
			$caKey,
			new DateTimeImmutable( '+1 day' ),
			new OpenSSLConfig( x509Extensions: OpenSSLConfig::X509_EXTENSION_CA ),
			1,
		);
		$userKey = new PrivateKey( new OpenSSLConfig( privateKeyType: OpenSSLKey::KEYTYPE_EC ) );
		$csrPem = CSR::generate( new DN( ['CN' => 'client@example.com'] ), $userKey )->getCSRPem();

		$recorder = $this->recordingCli();
		$signingKey = new Pkcs11SigningKey( $recorder, $caCert, 'pkcs11:object=test-ca-key', 'test-pin' );

		try {
			$signingKey->sign(
				$csrPem,
				new DN( ['CN' => 'client@example.com'] ),
				'basicConstraints = CA:FALSE',
				1234,
				new DateTimeImmutable( '-1 hour' ),
				new DateTimeImmutable( '+24 hours' ),
			);
			$this->fail( 'Expected sign() to fail because the recording CLI returns no certificate' );
		} catch ( UserException $e ) {
			$this->assertStringContainsString( 'no certificate', $e->getMessage() );
		}

		$captured = $recorder->lastArgs;
		$this->assertNotEmpty( $captured, 'The CLI was never invoked' );
		$commandIndex = \array_search( 'x509', $captured, true );
		$this->assertIsInt( $commandIndex, 'No x509 subcommand in argv' );

		// The actual VM bug: no -provider may appear before the subcommand
		foreach ( $captured as $index => $arg ) {
			if ( '-provider' === $arg ) {
				$this->assertGreaterThan( $commandIndex, $index, "-provider at position {$index} precedes 'x509' at {$commandIndex}" );
			}
		}

		// The default provider must be named explicitly next to pkcs11
		$this->assertContains( 'pkcs11', $captured );
		$this->assertContains( 'default', $captured );
	}

	/**
	 * A CLI that records argv instead of running anything; the empty return
	 * makes sign() fail with 'OpenSSL produced no certificate'.
	 */
	private function recordingCli(): OpenSSLCli
	{
		return new class() extends OpenSSLCli {
			/** @var array<string> */
			public array $lastArgs = [];

			public function run( array $args, array $extraEnv = [] ): string
			{
				$this->lastArgs = $args;

				return '';
			}
		};
	}
}
