<?php declare( strict_types=1 );

/*
 * This file is part of letswifi; a system for easy 802.1x device enrollment
 *
 * Copyright: Jørn Åne de Jong <jorn.dejong@letswifi.eu>
 * Copyright: Paul Dekkers, SURF <paul.dekkers@surf.nl>
 * SPDX-License-Identifier: BSD-3-Clause
 */

use letswifi\LetsWifiApp;
use letswifi\credential\CsrCredentialIssuer;
use letswifi\credential\CsrValidator;
use letswifi\error\HttpMethodException;
use letswifi\error\UserException;
use letswifi\format\Format;
use letswifi\profile\Realm;

require \implode( \DIRECTORY_SEPARATOR, [\dirname( __DIR__, 3 ), 'src', '_autoload.php'] );
\assert( \array_key_exists( 'REQUEST_METHOD', $_SERVER ) );

$app = new LetsWifiApp( basePath: '../..' );
$provider = $app->getProvider();

// Authentication is identical to the classic profile flow: browser session or
// OAuth2 bearer token; the requester identity is never taken from the CSR.
$user = $provider->requireAuth( scope: 'eap-metadata' );

switch ( $_SERVER['REQUEST_METHOD'] ) {
	case 'GET':
		$app->render( [
			'_description' => 'Submit a PKCS#10 certificate signing request (PEM or DER) as POST '
				. 'body or csr parameter; the server validates it, builds the certificate content '
				. 'itself, and returns the signed certificate and chain as PEM.',
			'realms' => \array_map(
				static fn( Realm $realm ): string => $realm->realmId,
				$user->getRealms(),
			),
		] );

		\assert( false, 'Unreachable code' );

		exit; // should not be reached
	case 'POST':
		$realmId = $_POST['realm'] ?? $_GET['realm'] ?? null;
		$realm = $user->getRealm( \is_string( $realmId ) ? $realmId : null );

		$csrInput = \readCsrInput();

		$validator = new CsrValidator( $app->profileService->getOpenSSLCli() );
		$csrPem = $validator->validate( $csrInput, \csrKeyPolicy( $realm ) );

		$issuer = new CsrCredentialIssuer(
			user: $user,
			realm: $realm,
			now: new DateTimeImmutable(),
			profileService: $app->profileService,
		);
		$credential = $issuer->issueFromCsr( $csrPem );

		$formatter = Format::getFormatter(
			'pem-certificate',
			credential: $credential,
			provider: $provider,
			translator: $app->getTranslationContext(),
		);
		$formatter->emit();
		\assert( false, 'Unreachable code' );

		exit; // should not be reached

	default:
		throw new HttpMethodException( ['POST', 'GET'] );
}

/**
 * The raw CSR from the request: form field, or the entire request body when
 * submitted with a certificate/PKCS10 content type.
 */
function readCsrInput(): string
{
	$csr = $_POST['csr'] ?? null;
	if ( \is_string( $csr ) && '' !== \trim( $csr ) ) {
		return $csr;
	}
	if ( \is_array( $csr ) ) {
		throw new UserException( 'Invalid CSR submitted', 400 );
	}

	$body = \file_get_contents( 'php://input' );
	$contentType = \strtolower( \trim( \explode( ';', $_SERVER['CONTENT_TYPE'] ?? '' )[0] ) );
	if ( false !== $body && '' !== \trim( $body ) && \in_array( $contentType, ['', 'application/pkcs10', 'application/pkcs10-csr', 'text/plain', 'application/x-pem-file', 'application/octet-stream'], true ) ) {
		return $body;
	}

	throw new UserException( 'No CSR provided', 400 );
}

/**
 * Per-realm key policy overrides; unconfigured realms get the CsrValidator
 * defaults (RSA >= 2048, EC P-256/P-384, no Ed25519).
 *
 * @return array<array-key,mixed>
 */
function csrKeyPolicy( Realm $realm ): array
{
	$policy = [];
	$rsaMin = $realm->getExtra( 'csr_rsa_min_bits' );
	if ( null !== $rsaMin ) {
		$policy['rsa_min_bits'] = (int)$rsaMin;
	}
	$curves = $realm->getExtra( 'csr_ec_curves' );
	if ( null !== $curves ) {
		$policy['ec_curves'] = \array_map( 'trim', \explode( ',', $curves ) );
	}
	$ed25519 = $realm->getExtra( 'csr_allow_ed25519' );
	if ( null !== $ed25519 ) {
		$policy['allow_ed25519'] = \filter_var( $ed25519, \FILTER_VALIDATE_BOOL );
	}

	return $policy;
}
