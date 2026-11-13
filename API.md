# API Usage

>[!CAUTION]
> The API code is not finished yet and breaking changes can be expected

Most operations that can be done through the web interface, can also be done through the API.
In order to use the API, you need an API token.

## Setting up an API account

Edit the `clients.conf.php` file and add the following:

```php
	'my.api.client.name' => [
		'clientId' => 'my.api.client.name',
		'scopes' => ['admin'],
		'clientSecret' => 'abc',
	],
```

Replace `my.api.client.name` with a name that you pick yourself.
Pick a secure and unguessable **clientSecret**.
Please be very sure that the name cannot collide with any username or affiliation.

In your provider configuration or realm configuration, make sure that this client ID is listed as adminstrator.

```php
	'admins' => [
		'my.api.client.name',
		// ..multiple admins..
	],
```

Now you can obtain your API key.

```sh
% curl -sS \
	-d grant_type=client_credentials \
	-d client_id=my.api.client.name \
	-d client_secret=abc \
	-d scope=admin \
	'https://HOSTNAME/oauth/token/'
```

If succesful, the result is a JSON document with a key called `access_token`.

You can use this API key in any request to the configuration panel.

## List and revoke current requesters

A requester is the actual identity of pseudo-credentials in the system.

```sh
% curl -HAuthorization:Bearer\ $TOKEN https://HOSTNAME/admin/requesters/
```

Returns JSON in the following format:

```json
{
	"requesters": {
		"samluser@realm.example.com": {
			"earliest_valid": "YYYY-MM-DD",
			"last_valid": "YYYY-MM-DD",
			"requester": {
				"name": "samluser",
				"realm": "realm.example.com"
			},
			"valid_on": "YYYY-MM-DDThh:mm:ss+00:00",
			"total_accounts": 5,
			"valid_accounts": 5
		}
	}
}
```

The `valid_on` is the current date and time; as other fields are influenced by the current time.

You can revoke someone like this, copy the `valid_on` field from your result, or build the value yourself using `date +%Y-%m-%dT%H:%M:%S+00:00`

```sh
% curl -sS --fail-with-body -HAuthorization:Bearer\ $TOKEN \
	-d revoke_requester=samluser \
	-d realms=realm.example.com \
	-d valid_on=$(date +%Y-%m-%dT%H:%M:%S+00:00) \
	https://HOSTNAME/admin/requesters/ \
```

Please note that at this time, the API will answer with 302 Found on success.
This will be fixed in a later release.

## Enroll from a client-generated CSR

`POST /profiles/csr/` accepts a PKCS#10 certificate signing request (PEM or
DER, max 16 KiB) and returns the signed client certificate plus chain as
PEM. The client keeps its private key; the server never sees it. Subject,
extensions and validity are set by the server from the authenticated
requester and realm configuration; anything the CSR asks for is ignored.

Authentication is identical to `/profiles/new/`: a browser session or an
OAuth2 bearer token with the `eap-metadata` scope. Optionally pass
`?realm=<id>` (or POST field `realm`) when the user has several realms.

```sh
% curl -sS --fail-with-body -HAuthorization:Bearer\ $TOKEN \
	-H 'Content-Type: application/pkcs10' \
	--data-binary @client.csr \
	'https://HOSTNAME/profiles/csr/'
```

Status codes:

- `200` — certificate and chain in PEM (no private key)
- `401` — missing or invalid authentication
- `400` — CSR rejected; the body starts with a machine-readable code:
  `no_csr`, `csr_invalid`, `csr_too_large`, `csr_malformed`,
  `rsa_too_small`, `curve_not_allowed`, `key_type_not_allowed`,
  `bad_signature`
- `429` — per-requester issuance limit reached (`Retry-After: 3600`);
  configurable per realm with the `csr_issuance_limit` extra
- `502` — the certificate signing backend (CA key or token) failed

## Generate CRL

```sh
% curl -sS --fail-with-body -HAuthorization:Bearer\ $TOKEN \
	--get -o "example.com Let's Wi-Fi CA.crl" \
	-d "ca=CN=example.com+Let's+Wi-Fi+CA" \
	-d file=crl-pem \
	'https://HOSTNAME/admin/realms/certificate.php'
```

or (identical effect)

```sh
% curl -sS --fail-with-body -HAuthorization:Bearer\ $TOKEN \
	-o "example.com Let's Wi-Fi CA.crl" \
	'https://HOSTNAME/admin/realms/certificate.php?realm_id=example.com&ca=CN%3Dexample.com+Let%27s+Wi-Fi+CA&file=crl-pem'
```

CRL generation requires a **file-based** CA key. For a realm whose CA key
lives on a PKCS#11 token this endpoint answers `501 Not Implemented`
(PKCS#11 CRL signing is planned but not implemented).
Other CA material (certificate, index) works for both CA types.
