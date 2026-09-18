<?php

declare(strict_types=1);

namespace IPmation;

/**
 * Structured result of a domain WHOIS lookup.
 */
final class WhoisInfo
{
    /**
     * @param string[] $status
     * @param string[] $nameservers
     */
    public function __construct(
        private readonly string $domain,
        private readonly ?string $registrar,
        private readonly array $status,
        private readonly ?string $created,
        private readonly ?string $updated,
        private readonly ?string $expires,
        private readonly array $nameservers,
        private readonly string $dnssec,
    ) {
    }

    public function getDomain(): string { return $this->domain; }
    public function getRegistrar(): ?string { return $this->registrar; }

    /** @return string[] */
    public function getStatus(): array { return $this->status; }

    public function getCreated(): ?string { return $this->created; }
    public function getUpdated(): ?string { return $this->updated; }
    public function getExpires(): ?string { return $this->expires; }

    /** @return string[] */
    public function getNameservers(): array { return $this->nameservers; }

    public function getDnssec(): string { return $this->dnssec; }
}
