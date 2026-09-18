<?php

declare(strict_types=1);

namespace IPmation;

/**
 * Structured result of an IP address lookup.
 */
final class IPInfo
{
    public function __construct(
        private readonly string $ip,
        private readonly ?string $city,
        private readonly ?string $region,
        private readonly ?string $country,
        private readonly ?string $postal,
        private readonly ?string $timezone,
        private readonly ?string $loc,
        private readonly ?string $isp,
        private readonly ?string $asn,
    ) {
    }

    public function getIp(): string { return $this->ip; }
    public function getCity(): ?string { return $this->city; }
    public function getRegion(): ?string { return $this->region; }
    public function getCountry(): ?string { return $this->country; }
    public function getPostal(): ?string { return $this->postal; }
    public function getTimezone(): ?string { return $this->timezone; }
    public function getLoc(): ?string { return $this->loc; }
    public function getIsp(): ?string { return $this->isp; }
    public function getAsn(): ?string { return $this->asn; }
}
