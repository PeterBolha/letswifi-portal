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
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use fyrkat\openssl\CSR;
use fyrkat\openssl\DN;
use fyrkat\openssl\OpenSSLConfig;
use fyrkat\openssl\OpenSSLKey;
use fyrkat\openssl\PrivateKey;
use fyrkat\openssl\X509;
use letswifi\signing\FileSigningKey;
use letswifi\signing\OpenSSLCli;

/**
 * Tests the openssl CLI signing path with a software CA key; this is the
 * code shared by file-based and PKCS#11 signing keys.
 */
class FileSigningKeyTest extends TestCase
{
	private const CA_DN = ['CN' => 'File Signing Test CA'];

	private const EXTENSIONS = <<<CONF
		subjectKeyIdentifier   = hash
		authorityKeyIdentifier = keyid:always, issuer:always
		basicConstraints       = CA:FALSE
		keyUsage               = digitalSignature, nonRepudiation, keyEncipherment
		extendedKeyUsage       = clientAuth
		CONF;

	private PrivateKey $caKey;

	private X509 $caCert;

	protected function setUp(): void
	{
		$this->caKey = new PrivateKey( new OpenSSLConfig( privateKeyType: OpenSSLKey::KEYTYPE_EC ) );
		$caDn = new DN( self::CA_DN );
		$caCsr = CSR::generate( $caDn, $this->caKey );
		$this->caCert = $caCsr->sign(
			null,
			$this->caKey,
			new DateTimeImmutable( '+1 day' ),
			new OpenSSLConfig( x509Extensions: OpenSSLConfig::X509_EXTENSION_CA ),
			1,
		);
	}

	public function testSignProducesValidCertificate(): void
	{
		$userKey = new PrivateKey( new OpenSSLConfig( privateKeyType: OpenSSLKey::KEYTYPE_EC ) );
		$clientDn = new DN( ['CN' => 'client-says-this'] );
		$clientCsr = CSR::generate( $clientDn, $userKey );

		$notBefore = new DateTimeImmutable( '-1 hour' );
		$notAfter = new DateTimeImmutable( '+24 hours' );
		$serverDn = new DN( ['CN' => 'a1b2c3d4e5f60718@example.com'] );

		$signingKey = new FileSigningKey( new OpenSSLCli(), $this->caCert, $this->caKey->getPrivateKeyPem( null ), null );
		$userCert = $signingKey->sign(
			$clientCsr->getCSRPem(),
			$serverDn,
			self::EXTENSIONS,
			4242,
			$notBefore,
			$notAfter,
		);

		// The subject must come from the server, never from the CSR
		$subject = (string)$userCert->getSubject();
		$this->assertStringContainsString( 'a1b2c3d4e5f60718@example.com', $subject );
		$this->assertStringNotContainsString( 'client-says-this', $subject );

		// Serial and validity window must match what the caller requested
		$this->assertSame( '4242', $userCert->getSerialNumber() );
		$this->assertSame( $notBefore->getTimestamp(), $userCert->getValidFrom()->getTimestamp() );
		$this->assertSame( $notAfter->getTimestamp(), $userCert->getValidTo()->getTimestamp() );

		// The certificate must verify against the CA and carry the client EAP-TLS extensions
		$this->assertTrue( $userCert->isSignedBy( $this->caCert ) );
		$this->assertFalse( $userCert->isCA() );
		$this->assertTrue( $userCert->checkKeyUsage( X509::KEY_USAGE_DIGITAL_SIGNATURE ) );
		$extensions = $userCert->getRawExtensions();
		$this->assertArrayHasKey( 'extendedKeyUsage', $extensions );
		$this->assertStringContainsString( 'Client Auth', (string)$extensions['extendedKeyUsage'] );

		// The certificate must contain the client's public key from the CSR
		$this->assertTrue( $userCert->checkPrivateKey( $userKey ) );
	}

	public function testDropsExtensionsRequestedInCsr(): void
	{
		$userKey = \openssl_pkey_new( ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'] );
		$this->assertNotFalse( $userKey );
		// The client requests CA:TRUE in the CSR; -clrext in the signing key
		// invocation must remove these before the server extensions are applied.
		$csrPem = $this->makeCsrWithRequestedExtensions( $userKey );

		$signingKey = new FileSigningKey( new OpenSSLCli(), $this->caCert, $this->caKey->getPrivateKeyPem( null ), null );
		$userCert = $signingKey->sign(
			$csrPem,
			new DN( ['CN' => 'harmless@example.com'] ),
			self::EXTENSIONS,
			4243,
			new DateTimeImmutable( '-1 hour' ),
			new DateTimeImmutable( '+24 hours' ),
		);

		$this->assertFalse( $userCert->isCA() );
		$extensions = $userCert->getRawExtensions();
		$this->assertArrayHasKey( 'basicConstraints', $extensions );
		$this->assertStringNotContainsString( 'CA:TRUE', (string)$extensions['basicConstraints'] );
		// And the server's own extensions must be present
		$this->assertArrayHasKey( 'extendedKeyUsage', $extensions );
	}

	/**
	 * A CSR that requests CA:TRUE through req_extensions, as a hostile client
	 * would submit.
	 */
	private function makeCsrWithRequestedExtensions( OpenSSLAsymmetricKey $key ): string
	{
		$configFile = \tempnam( \sys_get_temp_dir(), 'lwtest' );
		$this->assertIsString( $configFile );
		\file_put_contents( $configFile, <<<CONF
			[ req ]
			distinguished_name = req_dn
			req_extensions = req_evil

			[ req_dn ]

			[ req_evil ]
			basicConstraints = critical, CA:TRUE
			keyUsage = critical, digitalSignature, keyCertSign
			CONF );
		$csr = \openssl_csr_new(
			['CN' => 'evil-client'],
			$key,
			['config' => $configFile, 'req_extensions' => 'req_evil', 'digest_alg' => 'sha256'],
		);
		\unlink( $configFile );
		$this->assertNotFalse( $csr, \openssl_error_string() );
		$this->assertTrue( \openssl_csr_export( $csr, $pem ) );

		return $pem;
	}
}
