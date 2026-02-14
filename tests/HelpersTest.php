<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11\Tests;

use Nova\Bitcoin\Bolt11\Exception\InvalidAmountException;
use Nova\Bitcoin\Bolt11\Helpers;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the Helpers class.
 */
final class HelpersTest extends TestCase
{
    // ── satToHrp ──

    public function testSatToHrp250000(): void
    {
        self::assertSame('2500u', Helpers::satToHrp(250000));
    }

    public function testSatToHrp2000000(): void
    {
        self::assertSame('20m', Helpers::satToHrp(2000000));
    }

    public function testSatToHrp2500000(): void
    {
        self::assertSame('25m', Helpers::satToHrp(2500000));
    }

    public function testSatToHrp1000(): void
    {
        self::assertSame('10u', Helpers::satToHrp(1000));
    }

    public function testSatToHrp1Btc(): void
    {
        self::assertSame('1000m', Helpers::satToHrp(100000000));
    }

    public function testSatToHrp1Sat(): void
    {
        self::assertSame('10n', Helpers::satToHrp(1));
    }

    public function testSatToHrp10Sats(): void
    {
        self::assertSame('100n', Helpers::satToHrp(10));
    }

    // ── millisatToHrp ──

    public function testMillisatToHrp250000000(): void
    {
        self::assertSame('2500u', Helpers::millisatToHrp(250000000));
    }

    public function testMillisatToHrp967878534(): void
    {
        self::assertSame('9678785340p', Helpers::millisatToHrp(967878534));
    }

    public function testMillisatToHrpStringInput(): void
    {
        self::assertSame('2500u', Helpers::millisatToHrp('250000000'));
    }

    public function testMillisatToHrp1000(): void
    {
        self::assertSame('10n', Helpers::millisatToHrp(1000));
    }

    public function testMillisatToHrp100(): void
    {
        self::assertSame('1n', Helpers::millisatToHrp(100));
    }

    public function testMillisatToHrp1(): void
    {
        self::assertSame('10p', Helpers::millisatToHrp(1));
    }

    // ── hrpToSat ──

    public function testHrpToSat2500u(): void
    {
        self::assertSame('250000', Helpers::hrpToSat('2500u'));
    }

    public function testHrpToSat20m(): void
    {
        self::assertSame('2000000', Helpers::hrpToSat('20m'));
    }

    public function testHrpToSat25m(): void
    {
        self::assertSame('2500000', Helpers::hrpToSat('25m'));
    }

    public function testHrpToSat10u(): void
    {
        self::assertSame('1000', Helpers::hrpToSat('10u'));
    }

    public function testHrpToSat10n(): void
    {
        self::assertSame('1', Helpers::hrpToSat('10n'));
    }

    public function testHrpToSatFractionalThrows(): void
    {
        $this->expectException(InvalidAmountException::class);
        $this->expectExceptionMessage('not a whole number');

        Helpers::hrpToSat('9678785340p');
    }

    // ── hrpToMillisat ──

    public function testHrpToMillisat2500u(): void
    {
        self::assertSame('250000000', Helpers::hrpToMillisat('2500u'));
    }

    public function testHrpToMillisat20m(): void
    {
        self::assertSame('2000000000', Helpers::hrpToMillisat('20m'));
    }

    public function testHrpToMillisat9678785340p(): void
    {
        self::assertSame('967878534', Helpers::hrpToMillisat('9678785340p'));
    }

    public function testHrpToMillisat10n(): void
    {
        self::assertSame('1000', Helpers::hrpToMillisat('10n'));
    }

    public function testHrpToMillisat1n(): void
    {
        self::assertSame('100', Helpers::hrpToMillisat('1n'));
    }

    public function testHrpToMillisat10p(): void
    {
        self::assertSame('1', Helpers::hrpToMillisat('10p'));
    }

    public function testHrpToMillisatEmptyThrows(): void
    {
        $this->expectException(InvalidAmountException::class);

        Helpers::hrpToMillisat('');
    }

    public function testHrpToMillisatInvalidThrows(): void
    {
        $this->expectException(InvalidAmountException::class);

        Helpers::hrpToMillisat('abc');
    }

    public function testHrpToMillisatLeadingZeroThrows(): void
    {
        $this->expectException(InvalidAmountException::class);

        Helpers::hrpToMillisat('01u');
    }

    public function testHrpToMillisatPicoNotMultipleOf10Throws(): void
    {
        $this->expectException(InvalidAmountException::class);
        $this->expectExceptionMessage('pico-bitcoin');

        Helpers::hrpToMillisat('11p');
    }
}
