<h1>
  <img src="https://raw.githubusercontent.com/ipmation/assets/main/icon.svg" width="28" height="28" alt="IPmation" style="vertical-align:middle;margin-right:8px" />
  IPmation PHP Library
</h1>

A PHP library for IP address, WHOIS, and DNS lookups.

Provides three query methods with a consistent interface. Queries public
APIs and returns structured results. No local database, no caching layer,
no persistent state.

## Requirements

- PHP 8.1 or later
- Composer
- `ext-curl` and `ext-json` (both bundled by default)

## Installation

```bash
composer require ipmation/ipmation
```

## Usage

```php
use IPmation\IPmation;

$info = IPmation::lookupIP('8.8.8.8');
echo $info->getCity() . ' ' . $info->getCountry();

$me = IPmation::lookupIP();
echo $me->getIp();

$record = IPmation::lookupWhois('example.com');
echo $record->getRegistrar();

$answers = IPmation::lookupDns('example.com', 'MX');
foreach ($answers as $answer) {
    echo $answer . PHP_EOL;
}
```

## API Reference

| Method | Return type | Description |
| :--- | :--- | :--- |
| `lookupIP(string $ip = '')` | `IPInfo` | Returns geolocation, ISP, ASN, and timezone. Empty string resolves the caller's public IP. |
| `lookupWhois(string $domain)` | `WhoisInfo` | Returns registrar, status, dates, name servers, and DNSSEC status. |
| `lookupDns(string $domain, string $type = 'A')` | `string[]` | Returns DNS records. Supported types: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`. |

## Data Sources

This library does not maintain its own data. All queries are forwarded to
public APIs.

| Data | Source |
| :--- | :--- |
| IP geolocation, ISP, ASN | [ipinfo.io](https://ipinfo.io) |
| Domain registration | [rdap.org](https://rdap.org) |
| DNS records | [Cloudflare DNS-over-HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) |

## Scope

This library is not:

- An official SDK. It is a thin wrapper around public APIs.
- A self-hosted solution. Availability depends on the upstream sources listed above.
- A data provider. No IP data is stored, cached, or redistributed.

## Limitations

- IP geolocation accuracy is city-level.
- The free ipinfo.io tier enforces rate limits.
- RDAP coverage is incomplete. Certain country-code TLDs (`.cn`, `.me`) may return no data.
- DNS queries are routed through a public DoH endpoint and depend on its availability.

## License

MIT
