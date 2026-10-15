<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\signing;

use DateTimeImmutable;
use fyrkat\openssl\DN;
use fyrkat\openssl\X509;

/**
 * Abstraction over a CA key that can sign certificate signing requests.
 *
 * Implementations must never fall back to a different key type when the
 * configured key is unreachable; signing must fail closed.
 */
interface SigningKey
{
	/**
	 * Sign a CSR and return the resulting certificate.
	 *
	 * The subject, extensions, validity window and serial are all supplied by
	 * the caller; the implementation must not take any of these from the CSR.
	 *
	 * @param string            $csrPem     PEM encoded PKCS#10 request
	 * @param DN                $subject    Server-built subject
	 * @param string            $extensions OpenSSL extension config file contents (unnamed section)
	 * @param int               $serial     Certificate serial number
	 * @param DateTimeImmutable $notBefore  Start of validity
	 * @param DateTimeImmutable $notAfter   End of validity
	 */
	public function sign(
		string $csrPem,
		DN $subject,
		string $extensions,
		int $serial,
		DateTimeImmutable $notBefore,
		DateTimeImmutable $notAfter,
	): X509;
}
