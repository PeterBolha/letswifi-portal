<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\credential;

use DomainException;

/**
 * The random outer identity (the CN of issued certificates), built as
 * 16 random characters followed by @realm.
 */
final class Ident
{
	/**
	 * Create random string that ends with @realm
	 */
	public static function generate( string $realmId ): string
	{
		$realm = \rawurlencode( $realmId );
		if ( \strlen( $realm ) > 47 ) {
			throw new DomainException( 'Realm is too long to fit in certificate' );
		}

		// $local will be 16 bytes long
		$local = \strtolower( \strtr( \base64_encode( \random_bytes( 12 ) ), '/+9876', '012345' ) );
		\assert( \strlen( $local ) === 16 );

		// result is at most 47 + 1 + 16 = 64 bytes
		return "{$local}@{$realm}";
	}
}
