<?php

declare(strict_types=1);

namespace IPmation;

use RuntimeException;

/**
 * IPmation — a PHP library for IP, WHOIS, and DNS lookups.
 *
 * All queries are forwarded to public APIs and results are normalized
 * into the data models defined in this package.
 */
final class IPmation
{
    private const IPINFO_BASE = 'https://ipinfo.io';
    private const RDAP_BASE = 'https://rdap.org';
    private const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';

    private const TIMEOUT = 10;

    private const DNS_TYPES = ['A', 'NS', 'CNAME', 'MX', 'TXT', 'AAAA'];

    private function __construct()
    {
        // Utility class.
    }

    public static function lookupIP(string $ip = ''): IPInfo
    {
        $ip = trim($ip);
        $url = $ip === ''
            ? self::IPINFO_BASE . '/json'
            : self::IPINFO_BASE . '/' . $ip . '/json';

        $data = self::getJson($url);

        if (isset($data['error'])) {
            $message = $data['error']['message'] ?? 'unknown error';
            throw new RuntimeException('IP lookup failed: ' . $message);
        }

        [$asn, $isp] = self::parseOrg($data['org'] ?? '');

        return new IPInfo(
            $data['ip'] ?? 'Unknown',
            $data['city'] ?? null,
            $data['region'] ?? null,
            $data['country'] ?? null,
            $data['postal'] ?? null,
            $data['timezone'] ?? null,
            $data['loc'] ?? null,
            $isp,
            $asn,
        );
    }

    public static function lookupWhois(string $domain): WhoisInfo
    {
        $domain = self::normalizeDomain($domain);
        $url = self::RDAP_BASE . '/domain/' . $domain;

        [$status, $body] = self::request($url, ['Accept: application/rdap+json, application/json']);

        if ($status === 404) {
            throw new RuntimeException('Domain not found, or its registry does not support RDAP.');
        }
        if ($status !== 200) {
            throw new RuntimeException('Lookup failed: HTTP ' . $status);
        }

        $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

        if (isset($data['errorCode'])) {
            $message = $data['title'] ?? $data['description'] ?? 'Lookup failed.';
            throw new RuntimeException(is_string($message) ? $message : 'Lookup failed.');
        }

        return new WhoisInfo(
            $data['ldhName'] ?? $data['unicodeName'] ?? 'Unknown',
            self::extractRegistrar($data),
            $data['status'] ?? [],
            self::extractEventDate($data, 'registration'),
            self::extractEventDate($data, 'last changed'),
            self::extractEventDate($data, 'expiration'),
            self::extractNameservers($data),
            self::extractDnssec($data),
        );
    }

    /**
     * @return string[]
     */
    public static function lookupDns(string $domain, string $type = 'A'): array
    {
        $type = strtoupper($type);
        if (!in_array($type, self::DNS_TYPES, true)) {
            throw new RuntimeException('Unsupported record type: ' . $type);
        }

        $url = self::DOH_ENDPOINT . '?name=' . rawurlencode($domain) . '&type=' . $type;

        [$status, $body] = self::request($url, ['Accept: application/dns-json']);

        if ($status !== 200) {
            throw new RuntimeException('DNS query failed: HTTP ' . $status);
        }

        $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        $dnsStatus = $data['Status'] ?? 0;

        if ($dnsStatus === 3) {
            throw new RuntimeException('Domain does not exist.');
        }
        if ($dnsStatus !== 0) {
            throw new RuntimeException('DNS query returned status ' . $dnsStatus . '.');
        }

        $answers = [];
        foreach ($data['Answer'] ?? [] as $answer) {
            if (isset($answer['data'])) {
                $answers[] = $answer['data'];
            }
        }
        return $answers;
    }

    /**
     * @return array{0:int, 1:string}
     */
    private static function request(string $url, array $headers = []): array
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => self::TIMEOUT,
            CURLOPT_HTTPHEADER => $headers,
        ]);

        $body = curl_exec($ch);
        if ($body === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException('Request failed: ' . $error);
        }

        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return [$status, $body];
    }

    private static function getJson(string $url): array
    {
        [$status, $body] = self::request($url);

        if ($status !== 200) {
            throw new RuntimeException('Request failed: HTTP ' . $status);
        }

        return json_decode($body, true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * @return array{0:?string, 1:?string} [ASN, ISP]
     */
    private static function parseOrg(string $org): array
    {
        if ($org === '') {
            return [null, null];
        }
        $space = strpos($org, ' ');
        if ($space !== false && str_starts_with(strtoupper(substr($org, 0, $space)), 'AS')) {
            return [substr($org, 0, $space), substr($org, $space + 1)];
        }
        return [null, $org];
    }

    private static function normalizeDomain(string $domain): string
    {
        $result = strtolower(trim($domain));
        foreach (['https://', 'http://', 'www.'] as $prefix) {
            if (str_starts_with($result, $prefix)) {
                $result = substr($result, strlen($prefix));
            }
        }
        $slash = strpos($result, '/');
        return $slash !== false ? substr($result, 0, $slash) : $result;
    }

    private static function extractRegistrar(array $data): ?string
    {
        foreach ($data['entities'] ?? [] as $entity) {
            if (!in_array('registrar', $entity['roles'] ?? [], true)) {
                continue;
            }
            $vcard = $entity['vcardArray'] ?? null;
            if (!is_array($vcard) || count($vcard) < 2) {
                continue;
            }
            foreach ($vcard[1] as $entry) {
                if (($entry[0] ?? null) === 'fn' && isset($entry[3])) {
                    return $entry[3];
                }
            }
        }
        return null;
    }

    private static function extractEventDate(array $data, string $action): ?string
    {
        foreach ($data['events'] ?? [] as $event) {
            if (($event['eventAction'] ?? null) === $action) {
                $date = $event['eventDate'] ?? '';
                return $date !== '' ? substr($date, 0, 10) : null;
            }
        }
        return null;
    }

    /**
     * @return string[]
     */
    private static function extractNameservers(array $data): array
    {
        $result = [];
        foreach ($data['nameservers'] ?? [] as $ns) {
            if (isset($ns['ldhName'])) {
                $result[] = strtolower($ns['ldhName']);
            }
        }
        return $result;
    }

    private static function extractDnssec(array $data): string
    {
        return ($data['secureDNS']['delegationSigned'] ?? false) ? 'Signed' : 'Unsigned';
    }
}
