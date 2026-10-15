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
use DateTimeZone;
use fyrkat\openssl\DN;
use fyrkat\openssl\X509;
use letswifi\error\UserException;

/**
 * Shared `openssl x509 -req` invocation for CLI-backed signing keys.
 *
 * Subclasses only decide how the CA key and its PIN/passphrase are referenced;
 * the certificate content (subject, extensions, validity, serial) is built
 * here from caller-supplied values and never taken from the CSR.
 */
abstract class AbstractOpenSSLSigningKey implements SigningKey
{
	public function __construct( protected readonly OpenSSLCli $cli )
	{
	}

	final public function sign(
		string $csrPem,
		DN $subject,
		string $extensions,
		int $serial,
		DateTimeImmutable $notBefore,
		DateTimeImmutable $notAfter,
	): X509 {
		$csr = OpenSSLCli::dataFile( $csrPem, 'lwcsr' );
		$ext = OpenSSLCli::dataFile( $extensions, 'lwext' );
		$ca = OpenSSLCli::dataFile( $this->caCertificatePem(), 'lwca' );
		$out = OpenSSLCli::dataFile( '', 'lwcrt' );
		$key = $this->keyReference();

		try {
			$args = [
				...$this->providerArgs(),
				'x509',
				'-req',
				'-in', $csr->path,
				'-CA', $ca->path,
				'-CAkey', $key->keyArgument,
				'-not_before', static::formatTimestamp( $notBefore ),
				'-not_after', static::formatTimestamp( $notAfter ),
				'-set_serial', (string)$serial,
				'-subj', static::subjectToSlash( $subject ),
				'-clrext',
				'-extfile', $ext->path,
				'-out', $out->path,
			];
			if ( null !== $key->passin ) {
				$args[] = '-passin';
				$args[] = $key->passin->asPassinFile();
			}
			$this->cli->run( $args, $this->childEnvironment() );

			$pem = \file_get_contents( $out->path );
			if ( false === $pem || !\str_contains( $pem, 'BEGIN' ) ) {
				throw new UserException( 'OpenSSL produced no certificate' );
			}

			return new X509( $pem );
		} finally {
			$csr->cleanup();
			$ext->cleanup();
			$ca->cleanup();
			$out->cleanup();
			$key->cleanup();
		}
	}

	/**
	 * Convert a DN to the OpenSSL `/type=value` argument format, escaping
	 * backslashes and forward slashes.
	 */
	final public static function subjectToSlash( DN $subject ): string
	{
		$parts = [];
		foreach ( $subject->toArray() as $type => $value ) {
			foreach ( (array)$value as $single ) {
				$escaped = \str_replace( ['\\', '/'], ['\\\\', '\\/'], (string)$single );
				$parts[] = "/{$type}={$escaped}";
			}
		}

		return \implode( '', $parts );
	}

	final public static function formatTimestamp( DateTimeImmutable $time ): string
	{
		return $time->setTimezone( new DateTimeZone( 'UTC' ) )->format( 'YmdHis\\Z' );
	}

	/**
	 * PEM of the certificate that corresponds to the signing key.
	 */
	abstract protected function caCertificatePem(): string;

	/**
	 * The `-CAkey` and optional `-passin` arguments for one signing operation,
	 * with any temporary files that must be removed afterwards.
	 */
	abstract protected function keyReference(): KeyReference;

	/**
	 * Arguments to place before the `x509` subcommand, e.g. to load a
	 * provider.  Must not contain secrets.
	 *
	 * @return array<string> arguments, each a single argv element
	 */
	protected function providerArgs(): array
	{
		return [];
	}

	/**
	 * Additional environment variables for the signing subprocess.  Merged
	 * into the allowlisted parent environment; must never contain secrets.
	 *
	 * @return array<string,string>
	 */
	protected function childEnvironment(): array
	{
		return [];
	}
}
