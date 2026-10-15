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
 * The `-CAkey`/`-passin` arguments produced for one signing operation, plus
 * the temporary files that hold them, which must be removed when the
 * operation finishes.
 */
final class KeyReference
{
	/** @param list<DataFile|SecretFile> $cleanup */
	public function __construct(
		public readonly string $keyArgument,
		public readonly ?SecretFile $passin,
		private readonly array $cleanup = [],
	) {
	}

	public function __destruct()
	{
		$this->cleanup();
	}

	public function cleanup(): void
	{
		foreach ( $this->cleanup as $file ) {
			$file->cleanup();
		}
	}
}
