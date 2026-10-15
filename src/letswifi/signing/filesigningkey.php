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

/**
 * Signs with a PEM encoded CA key held in configuration.
 *
 * The key material is written to a mode 0600 temporary file for the duration
 * of the signing command; it never appears in process arguments.
 */
class FileSigningKey extends AbstractOpenSSLSigningKey
{
	public function __construct(
		OpenSSLCli $cli,
		private readonly X509 $certificate,
		private readonly string $keyPem,
		private readonly ?string $passphrase,
	) {
		parent::__construct( $cli );
	}

	protected function caCertificatePem(): string
	{
		return $this->certificate->getX509Pem();
	}

	protected function keyReference(): KeyReference
	{
		$keyFile = OpenSSLCli::secretFile( $this->keyPem );
		$passin = null === $this->passphrase ? null : OpenSSLCli::secretFile( $this->passphrase );

		return new KeyReference( $keyFile->path, $passin, [$keyFile] );
	}
}
