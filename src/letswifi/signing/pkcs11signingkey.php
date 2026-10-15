<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\signing;

use fyrkat\openssl\X509;
use letswifi\error\UserException;

/**
 * Signs using a CA key held in a PKCS#11 token (network HSM or software
 * token), referenced by a RFC 7512 pkcs11: URI, using the OpenSSL 3 PKCS#11
 * provider.
 *
 * The token PIN is never part of the URI or of any process argument; it is
 * written to a mode 0600 temporary file and passed as a -passin file source.
 *
 * If the token is unreachable or the key is missing, the underlying OpenSSL
 * command fails and signing fails with it.  There is no fallback to other
 * key types.
 */
class Pkcs11SigningKey extends AbstractOpenSSLSigningKey
{
	/**
	 * @param string  $uri    RFC 7512 pkcs11: URI selecting the private key object
	 * @param string  $pin    Token PIN; keep out of logs and configuration in source control
	 * @param ?string $module Path to the PKCS#11 module, exported as PKCS11_PROVIDER_MODULE
	 */
	public function __construct(
		OpenSSLCli $cli,
		private readonly X509 $certificate,
		private readonly string $uri,
		private readonly string $pin,
		private readonly ?string $module = null,
	) {
		parent::__construct( $cli );
		if ( !\str_starts_with( $uri, 'pkcs11:' ) ) {
			throw new UserException( 'Invalid PKCS#11 key URI' );
		}
		if ( '' === $pin ) {
			throw new UserException( 'Empty PKCS#11 token PIN' );
		}
	}

	protected function caCertificatePem(): string
	{
		return $this->certificate->getX509Pem();
	}

	protected function keyReference(): KeyReference
	{
		$pin = OpenSSLCli::secretFile( $this->pin );

		return new KeyReference( $this->uri, $pin, [$pin] );
	}

	protected function providerArgs(): array
	{
		// The default provider must be named explicitly: loading a specific
		// provider on the command line switches off the implicit defaults,
		// which would remove the X.509 and digest algorithms we need.
		return ['-provider', 'default', '-provider', 'pkcs11'];
	}

	protected function childEnvironment(): array
	{
		if ( null === $this->module ) {
			return [];
		}

		return ['PKCS11_PROVIDER_MODULE' => $this->module];
	}
}
