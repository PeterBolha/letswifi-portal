<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\signing;

use letswifi\error\UserException;

/**
 * Runs the OpenSSL command line tool with argument arrays only.
 *
 * Secrets (key passphrases, PKCS#11 token PINs) are deliberately kept out of
 * the process arguments, because argv is world-readable via `ps`.  They are
 * delivered as the mode 0600 file returned by secretFile() and referenced
 * from a `passin:file:` argument, which does not leak the secret value.
 *
 * The environment passed to the child is an allowlist derived from the parent
 * environment, so secrets can never leak through an inherited variable.
 */
class OpenSSLCli
{
	/**
	 * Environment variables the OpenSSL tool may need from the parent.
	 * Anything that could contain secrets is excluded by construction.
	 * SOFTHSM2_CONF and OPENSSL_MODULES are configuration paths like
	 * OPENSSL_CONF; they contain no secret values.
	 */
	private const ENV_ALLOWLIST = ['PATH', 'HOME', 'LANG', 'LC_ALL', 'OPENSSL_CONF', 'OPENSSL_MODULES', 'SOFTHSM2_CONF'];

	public function __construct( private readonly string $binary = 'openssl' )
	{
	}

	/**
	 * A file only this process can read, holding a secret, to be referenced
	 * from a `passin:file:` argument.
	 *
	 * The caller MUST call cleanup() when done with the returned file.
	 */
	public static function secretFile( string $secret ): SecretFile
	{
		if ( \strlen( $secret ) > 4096 ) {
			throw new UserException( 'Secret too large' );
		}
		$path = \tempnam( \sys_get_temp_dir(), 'lwsec' );
		if ( false === $path ) {
			throw new UserException( 'Unable to create temporary file' );
		}
		\chmod( $path, 0o600 );
		if ( false === \file_put_contents( $path, $secret ) ) {
			\unlink( $path );

			throw new UserException( 'Unable to write temporary file' );
		}

		return new SecretFile( $path );
	}

	/**
	 * Create a mode 0600 file with arbitrary content for use as an input or
	 * config file of an OpenSSL command.
	 */
	public static function dataFile( string $content, string $prefix = 'lwdat' ): DataFile
	{
		$path = \tempnam( \sys_get_temp_dir(), $prefix );
		if ( false === $path ) {
			throw new UserException( 'Unable to create temporary file' );
		}
		\chmod( $path, 0o600 );
		if ( false === \file_put_contents( $path, $content ) ) {
			\unlink( $path );

			throw new UserException( 'Unable to write temporary file' );
		}

		return new DataFile( $path );
	}

	/**
	 * Run openssl with an argument array.
	 *
	 * Arguments are passed directly to the process without a shell in between,
	 * so no escaping is needed (or wanted) anywhere.
	 *
	 * @param array<string>        $args     Arguments, each a single argv element
	 * @param array<string,string> $extraEnv Additional environment for this
	 *                                       call only; must never contain secrets
	 *
	 * @throws UserException when the command fails; the message contains the
	 *                       openssl error output but never the arguments
	 *
	 * @return string Raw standard output
	 */
	public function run( array $args, array $extraEnv = [] ): string
	{
		// stderr goes to a file, not a pipe: a blocked stdout read while the
		// child fills the stderr pipe buffer would deadlock the subprocess.
		$errorFile = self::dataFile( '', 'lwerr' );
		$descriptors = [
			0 => ['pipe', 'r'],
			1 => ['pipe', 'w'],
			2 => ['file', $errorFile->path, 'w'],
		];
		// Array form: no shell is involved at all, so no argument can be
		// re-interpreted as shell syntax (string form would need
		// escapeshellcmd, which mangles valid openssl arguments)
		$process = \proc_open( [$this->binary, ...$args], $descriptors, $pipes, null, $this->buildEnvironment( $extraEnv ) );
		if ( !\is_resource( $process ) ) {
			$errorFile->cleanup();

			throw new UserException( 'Unable to start OpenSSL' );
		}

		try {
			\fclose( $pipes[0] );
			$out = \stream_get_contents( $pipes[1] );
			\fclose( $pipes[1] );
			$exit = \proc_close( $process );
			$process = null;
			$err = (string)\file_get_contents( $errorFile->path );
			$errorFile->cleanup();
			if ( 0 !== $exit ) {
				// Never include $command or $args; openssl error output may quote
				// file names, but those are random temp paths, never secret values
				throw new UserException( \sprintf( 'OpenSSL command failed (exit %d): %s', $exit, \trim( \substr( $err, 0, 500 ) ) ?: 'no error output') );
			}
			if ( !\is_string( $out ) ) {
				throw new UserException( 'Unable to read OpenSSL output' );
			}

			return $out;
		} finally {
			foreach ( $pipes as $pipe ) {
				if ( \is_resource( $pipe ) ) {
					\fclose( $pipe );
				}
			}
			if ( \is_resource( $process ) ) {
				\proc_terminate( $process );
				\proc_close( $process );
			}
		}
	}

	/**
	 * @param array<string,string> $extraEnv
	 *
	 * @return array<string,string>
	 */
	private function buildEnvironment( array $extraEnv = [] ): array
	{
		$env = [];
		foreach ( self::ENV_ALLOWLIST as $name ) {
			$value = \getenv( $name );
			if ( false !== $value ) {
				$env[$name] = $value;
			}
		}

		return \array_merge( $env, $extraEnv );
	}
}
