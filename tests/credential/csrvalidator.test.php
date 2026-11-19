<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\test\credential;

use PHPUnit\Framework\TestCase;
use letswifi\credential\CsrValidator;
use letswifi\error\UserException;
use letswifi\signing\OpenSSLCli;

/**
 * Unit tests for CSR validation; these use software keys only, no token.
 */
class CsrValidatorTest extends TestCase
{
	private CsrValidator $validator;

	protected function setUp(): void
	{
		$this->validator = new CsrValidator( new OpenSSLCli() );
	}

	public function testAcceptsValidEcP256(): void
	{
		$pem = $this->makeCsr( ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'] );
		$result = $this->validator->validate( $pem );
		$this->assertStringContainsString( '-----BEGIN CERTIFICATE REQUEST-----', $result );
	}

	public function testAcceptsValidEcP384(): void
	{
		$pem = $this->makeCsr( ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1'] );
		$this->assertStringContainsString( '-----BEGIN CERTIFICATE REQUEST-----', $this->validator->validate( $pem ) );
	}

	public function testAcceptsRsa2048(): void
	{
		$pem = $this->makeCsr( ['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048] );
		$this->assertStringContainsString( '-----BEGIN CERTIFICATE REQUEST-----', $this->validator->validate( $pem ) );
	}

	public function testRejectsRsaTooSmall(): void
	{
		$pem = $this->makeCsr( ['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 1024] );
		$this->expectException( UserException::class );
		$this->expectExceptionCode( 400 );
		$this->expectExceptionMessageMatches( '/^rsa_too_small: /' );
		$this->validator->validate( $pem );
	}

	public function testRejectsDisallowedEcCurve(): void
	{
		$pem = $this->makeCsr( ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1'] );
		$this->expectException( UserException::class );
		$this->expectExceptionCode( 400 );
		$this->expectExceptionMessageMatches( '/^curve_not_allowed: /' );
		$this->validator->validate( $pem );
	}

	public function testPerRealmPolicyCanRaiseMinimum(): void
	{
		$pem = $this->makeCsr( ['private_key_type' => \OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048] );
		$this->expectException( UserException::class );
		$this->expectExceptionCode( 400 );
		$this->expectExceptionMessageMatches( '/^rsa_too_small: /' );
		$this->validator->validate( $pem, ['rsa_min_bits' => 4096] );
	}

	public function testPerRealmPolicyCanAllowExtraCurve(): void
	{
		$pem = $this->makeCsr( ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp521r1'] );
		$result = $this->validator->validate( $pem, ['ec_curves' => ['prime256v1', 'secp521r1']] );
		$this->assertStringContainsString( '-----BEGIN CERTIFICATE REQUEST-----', $result );
	}

	public function testRejectsEmpty(): void
	{
		$this->expectException( UserException::class );
		$this->expectExceptionCode( 400 );
		$this->expectExceptionMessageMatches( '/^no_csr: /' );
		$this->validator->validate( '   ' );
	}

	public function testRejectsOversized(): void
	{
		$this->expectException( UserException::class );
		$this->expectExceptionCode( 400 );
		$this->expectExceptionMessageMatches( '/^csr_too_large: /' );
		$this->validator->validate( \str_repeat( 'A', CsrValidator::MAX_INPUT_SIZE + 1 ) );
	}

	public function testRejectsMalformed(): void
	{
		$this->expectException( UserException::class );
		$this->expectExceptionCode( 400 );
		$this->expectExceptionMessageMatches( '/^csr_malformed: /' );
		$this->validator->validate( "-----BEGIN CERTIFICATE REQUEST-----\nnot base64 at all @@@\n-----END CERTIFICATE REQUEST-----\n" );
	}

	/**
	 * Input without a PEM marker is handed to OpenSSL as DER; when OpenSSL
	 * cannot load it at all, that is a client error, not a server error.
	 */
	public function testRejectsMalformedDer(): void
	{
		$this->expectException( UserException::class );
		$this->expectExceptionCode( 400 );
		$this->expectExceptionMessageMatches( '/^csr_malformed: /' );
		$this->validator->validate( "this is not a CSR at all\n" );
	}

	/**
	 * A truncated DER request fails ASN.1 parsing with "not enough data"; it
	 * must not surface as an unhandled failure either.
	 */
	public function testRejectsTruncatedDer(): void
	{
		$pem = $this->makeCsr( ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'] );
		$truncated = \substr( $this->pemToDer( $pem ), 0, 40 );

		$this->expectException( UserException::class );
		$this->expectExceptionCode( 400 );
		$this->expectExceptionMessageMatches( '/^csr_malformed: /' );
		$this->validator->validate( $truncated );
	}

	/**
	 * The rejection reason is shown to the client verbatim, so it must stay a
	 * fixed string: OpenSSL error output names include directories and
	 * temporary file paths of the server.
	 */
	public function testMalformedDerMessageDoesNotLeakOpenSslOutput(): void
	{
		try {
			$this->validator->validate( "this is not a CSR at all\n" );
			$this->fail( 'Expected unparseable DER input to be rejected' );
		} catch ( UserException $e ) {
			$this->assertSame( 'csr_malformed: Malformed CSR', $e->getMessage() );
			$this->assertStringNotContainsString( 'OpenSSL', $e->getMessage() );
		}
	}

	public function testAcceptsDerInput(): void
	{
		$pem = $this->makeCsr( ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'] );
		$result = $this->validator->validate( $this->pemToDer( $pem ) );
		$this->assertStringContainsString( '-----BEGIN CERTIFICATE REQUEST-----', $result );
	}

	public function testRejectsBadSelfSignature(): void
	{
		$pem = $this->makeCsr( ['private_key_type' => \OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'] );
		$der = $this->pemToDer( $pem );

		// Corrupt the final byte of the DER: it lies inside the signature bit
		// string, so the structure stays valid but the self-signature breaks,
		// which proof-of-possession verification must reject.
		$der[\strlen( $der ) - 1] = \chr( \ord( $der[\strlen( $der ) - 1] ) ^ 0x01 );

		// Must stay bad_signature and not degrade into csr_malformed: clients
		// distinguish "could not parse" from "you do not hold the key".
		$this->expectException( UserException::class );
		$this->expectExceptionCode( 400 );
		$this->expectExceptionMessageMatches( '/^bad_signature: /' );
		$this->validator->validate( $der );
	}

	/**
	 * @param array<string,mixed> $keyOpts
	 */
	private function makeCsr( array $keyOpts, string $cn = 'csr.example' ): string
	{
		$key = \openssl_pkey_new( $keyOpts );
		$this->assertNotFalse( $key, 'Failed to generate key: ' . \openssl_error_string() );
		$csr = \openssl_csr_new( ['CN' => $cn], $key, ['digest_alg' => 'sha256'] );
		$this->assertNotFalse( $csr, 'Failed to create CSR: ' . \openssl_error_string() );
		$this->assertTrue( \openssl_csr_export( $csr, $pem ) );

		return $pem;
	}

	private function pemToDer( string $pem ): string
	{
		$body = \preg_replace( '/-----(BEGIN|END)[^-]*-----|\\s/', '', $pem );
		$this->assertIsString( $body );
		$der = \base64_decode( $body, true );
		$this->assertNotFalse( $der );

		return $der;
	}
}
