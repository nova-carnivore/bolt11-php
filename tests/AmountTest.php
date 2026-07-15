<?php

declare(strict_types=1);

namespace Nova\Bitcoin\Bolt11\Tests;

use Nova\Bitcoin\Bolt11\Amount;
use Nova\Bitcoin\Bolt11\Exception\InvalidAmountException;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the integer-typed Amount value object.
 *
 * `millisatoshis` is an `int` (not a string): a BOLT 11 amount is always a whole
 * number of msat and is capped at the 21M BTC supply, so strict numeric
 * comparison works and there is no string/int mismatch footgun.
 */
final class AmountTest extends TestCase
{
    public function testMillisatoshisIsIntAndComparesWithStrictEquality(): void
    {
        // assertSame is a strict === check: an int value compares cleanly
        // against an int literal, which is the whole point of the refactor
        // (a string "967878534" would silently never === 967878534).
        $amount = Amount::fromHrp('9678785340p');
        self::assertSame(967878534, $amount->millisatoshis);
    }

    public function testSatoshisAccessor(): void
    {
        self::assertSame(250000, Amount::fromHrp('2500u')->satoshis());
        // Sub-satoshi amount: satoshis() is null, msat is still exact.
        $sub = Amount::fromHrp('9678785340p');
        self::assertNull($sub->satoshis());
        self::assertSame(967878534, $sub->millisatoshis);
    }

    public function testMillisatoshisString(): void
    {
        self::assertSame('250000000', Amount::fromHrp('2500u')->millisatoshisString());
    }

    public function testFromMillisatoshisAcceptsIntAndString(): void
    {
        self::assertSame(1500, Amount::fromMillisatoshis(1500)->millisatoshis);
        self::assertSame(1500, Amount::fromMillisatoshis('1500')->millisatoshis);
    }

    /**
     * The 21M cap is enforced on every construction path, not only on decode,
     * so a caller cannot smuggle an out-of-range value in via the string form.
     */
    public function testFromMillisatoshisRejectsOversizedString(): void
    {
        $this->expectException(InvalidAmountException::class);
        Amount::fromMillisatoshis('99999999999999999999999');
    }

    public function testFromMillisatoshisRejectsNonNumericString(): void
    {
        $this->expectException(InvalidAmountException::class);
        Amount::fromMillisatoshis('12ab');
    }

    public function testConstructorRejectsNegative(): void
    {
        $this->expectException(InvalidAmountException::class);
        new Amount(-1);
    }

    public function testConstructorRejectsAboveCap(): void
    {
        $this->expectException(InvalidAmountException::class);
        new Amount(Amount::MAX_MSAT + 1);
    }

    public function testFromSatoshisRejectsOversized(): void
    {
        $this->expectException(InvalidAmountException::class);
        Amount::fromSatoshis(intdiv(Amount::MAX_MSAT, 1000) + 1);
    }

    public function testFromSatoshisRejectsNegative(): void
    {
        $this->expectException(InvalidAmountException::class);
        Amount::fromSatoshis(-1);
    }
}
