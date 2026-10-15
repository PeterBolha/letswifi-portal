<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\format;

use DomainException;
use letswifi\credential\CsrCredential;

/**
 * Issues the certificate and its chain as PEM, without any private key.
 *
 * Only usable for CSR-based credentials: the client generated its own keypair
 * and only needs the signed certificate to complete EAP-TLS enrollment.
 */
class PemCertificateFormat extends Format
{
	public function getFileExtension(): string
	{
		return 'pem';
	}

	public function getContentType(): string
	{
		return 'application/x-x509-user-cert';
	}

	public function generate(): string
	{
		if ( !$this->credential instanceof CsrCredential ) {
			throw new DomainException( 'PEM certificate output is only available for CSR issued credentials' );
		}
		$payload = $this->credential->getPayload();

		return $payload['x509'] . \implode( '', $payload['chain'] );
	}
}
