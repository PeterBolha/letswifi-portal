<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\signing;

/**
 * A mode 0600 temporary file used as input or config for an OpenSSL command.
 */
class DataFile
{
	private bool $cleaned = false;

	public function __construct( public readonly string $path )
	{
	}

	public function __destruct()
	{
		$this->cleanup();
	}

	public function cleanup(): void
	{
		// cleanup() runs from both explicit calls and the destructor; the
		// unlink must only be attempted once, so that the second call does
		// not warn about an already deleted file
		if ( $this->cleaned ) {
			return;
		}
		$this->cleaned = true;
		\unlink( $this->path );
	}
}
