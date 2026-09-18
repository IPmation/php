<?php

declare(strict_types=1);

namespace IPmation\Tests;

use IPmation\IPmation;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Basic integration tests for the IPmation library.
 *
 * These tests require network access to ipinfo.io, rdap.org, and
 * Cloudflare DNS-over-HTTPS.
 */
final class IPmationTest extends TestCase
{
    public function testLookupIpReturnsStructuredData(): void
    {
        $info = IPmation::lookupIP('8.8.8.8');
        $this->assertSame('8.8.8.8', $info->getIp());
        $this->assertNotNull($info->getCountry());
        $this->assertNotNull($info->getAsn());
        $this->assertNotNull($info->getIsp());
    }

    public function testLookupWhoisReturnsRegistrar(): void
    {
        $record = IPmation::lookupWhois('example.com');
        $this->assertSame('example.com', strtolower($record->getDomain()));
        $this->assertNotNull($record->getRegistrar());
    }

    public function testLookupDnsReturnsRecords(): void
    {
        $answers = IPmation::lookupDns('example.com', 'A');
        $this->assertNotEmpty($answers);
    }

    public function testLookupDnsRejectsUnknownRecordType(): void
    {
        $this->expectException(RuntimeException::class);
        IPmation::lookupDns('example.com', 'INVALID');
    }
}
