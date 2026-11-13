<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\credential;

use letswifi\error\UserException;
use letswifi\signing\OpenSSLCli;

/**
 * Validation of client-provided PKCS#10 certificate signing requests.
 *
 * Only the public key of the CSR is trusted to be meaningful; subject and
 * extensions requested in the CSR are ignored by the issuer.
 *
 * Rejections throw UserException with HTTP 400 and a machine-readable
 * error code as message prefix ("code: human readable text"), documented
 * in API.md under the /profiles/csr/ endpoint.
 */
final class CsrValidator
{
	/**
	 * Maximum accepted CSR size in bytes; a DER PKCS#10 request with an
	 * RSA-8192 public key is still far below this.
	 */
	public const MAX_INPUT_SIZE = 16384;

	/**
	 * Key policy defaults: RSA >= 2048 bits, EC P-256 or P-384, nothing else.
	 *
	 * @var array{rsa_min_bits:int,ec_curves:array<string>,allow_ed25519:bool}
	 */
	public const DEFAULT_POLICY = [
		'rsa_min_bits' => 2048,
		'ec_curves' => ['prime256v1', 'secp384r1'],
		'allow_ed25519' => false,
	];

	public function __construct( private readonly OpenSSLCli $cli )
	{
	}

	/**
	 * Validate a CSR given as PEM or DER and return it normalised to PEM.
	 *
	 * Rejects oversized or malformed input, enforces the key policy, and
	 * verifies the CSR self-signature (proof of possession of the private
	 * key) before the request can be signed.
	 *
	 * @param array<array-key,mixed> $policy key policy as in DEFAULT_POLICY
	 *
	 * @throws UserException with a client-presentable reason
	 */
	public function validate( string $input, array $policy = [] ): string
	{
		if ( '' === \trim( $input ) ) {
			throw new UserException( 'no_csr: No CSR provided', 400 );
		}
		if ( \strlen( $input ) > self::MAX_INPUT_SIZE ) {
			throw new UserException( 'csr_too_large: CSR too large', 400 );
		}

		$csrPem = \str_contains( $input, '-----BEGIN' ) ? $input : $this->derToPem( $input );

		$this->checkKeyPolicy( $csrPem, self::DEFAULT_POLICY === $policy ? self::DEFAULT_POLICY : $policy + self::DEFAULT_POLICY );
		$this->verifySelfSignature( $csrPem );

		return $csrPem;
	}

	private function derToPem( string $der ): string
	{
		$in = OpenSSLCli::dataFile( $der, 'lwdsr' );
		$out = OpenSSLCli::dataFile( '', 'lwdsp' );
		$this->cli->run( ['req', '-inform', 'der', '-in', $in->path, '-outform', 'pem', '-out', $out->path] );
		$pem = \file_get_contents( $out->path );
		if ( false === $pem || !\str_contains( $pem, '-----BEGIN' ) ) {
			throw new UserException( 'csr_malformed: Malformed CSR', 400 );
		}

		return $pem;
	}

	/**
	 * Parse the public key of the CSR and enforce the key policy.
	 *
	 * Uses the PHP OpenSSL extension; this is pure software parsing, no
	 * subprocess and no token involved.
	 *
	 * @param array{rsa_min_bits:int,ec_curves:array<array-key,mixed>,allow_ed25519:bool} $policy
	 */
	private function checkKeyPolicy( string $csrPem, array $policy ): void
	{
		$publicKey = \openssl_csr_get_public_key( $csrPem, false );
		if ( false === $publicKey ) {
			throw new UserException( 'csr_malformed: Malformed CSR', 400 );
		}
		$details = \openssl_pkey_get_details( $publicKey );
		if ( false === $details ) {
			throw new UserException( 'csr_malformed: Malformed CSR', 400 );
		}

		$curves = \array_map( 'strval', (array)$policy['ec_curves'] );

		switch ( $details['type'] ) {
			case \OPENSSL_KEYTYPE_RSA:
				if ( $details['bits'] < $policy['rsa_min_bits'] ) {
					throw new UserException( "rsa_too_small: RSA key too small; minimum is {$policy['rsa_min_bits']} bits", 400 );
				}
				break;

			case \OPENSSL_KEYTYPE_EC:
				$curve = (string)( $details['ec']['curve_name'] ?? '' );
				if ( !\in_array( $curve, $curves, true ) ) {
					throw new UserException( "curve_not_allowed: EC curve {$curve} is not allowed", 400 );
				}
				break;

			default:
				$ed25519 = \defined( '\\OPENSSL_KEYTYPE_ED25519' ) && \OPENSSL_KEYTYPE_ED25519 === $details['type'];
				if ( !( $ed25519 && true === $policy['allow_ed25519'] ) ) {
					throw new UserException( 'key_type_not_allowed: Key type is not allowed', 400 );
				}
		}
	}

	/**
	 * Verify the CSR self-signature, proving possession of the private key.
	 *
	 * The PHP OpenSSL extension cannot verify a PKCS#10 request; `openssl
	 * req -verify` exits non-zero when the signature does not match.
	 */
	private function verifySelfSignature( string $csrPem ): void
	{
		$csr = OpenSSLCli::dataFile( $csrPem, 'lwvrf' );

		try {
			$this->cli->run( ['req', '-in', $csr->path, '-verify', '-noout'] );
		} catch ( UserException $e ) {
			throw new UserException( 'bad_signature: CSR signature verification failed', 400 );
		}
	}
}
