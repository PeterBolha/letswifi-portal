<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

namespace letswifi\test\credential;

use DomainException;
use PHPUnit\Framework\TestCase;
use letswifi\credential\Ident;

class IdentTest extends TestCase
{
	public function testFormat(): void
	{
		$ident = Ident::generate( 'example.com' );
		$this->assertMatchesRegularExpression( '/^[0-9a-z]{16}@example\\.com$/', $ident );
	}

	public function testLength(): void
	{
		$this->assertLessThanOrEqual( 64, \strlen( Ident::generate( 'some.long.example.realm.example.com' ) ) );
		$this->assertLessThanOrEqual( 64, \strlen( Ident::generate( 'example.com' ) ) );
	}

	public function testRandomness(): void
	{
		$gen = [];
		for ( $i = 0; 100 > $i; ++$i ) {
			$gen[] = Ident::generate( 'example.com' );
		}
		$this->assertCount( 100, \array_unique( $gen ) );
	}

	public function testTooLongRealm(): void
	{
		$this->expectException( DomainException::class );
		Ident::generate( \str_repeat( 'ä', 34 ) ); // rawurlencode makes each byte 3 chars
	}
}
