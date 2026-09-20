using Tessera.Nxpsc.Mock;

namespace Tessera.Nxpsc.Tests;

/// <summary>
/// Whole flows through the binding, the transport callback and libnxpsc against
/// libnxpsc's mock card: real framing, real crypto on both sides.
/// </summary>
public class MockCardTests
{
    private static readonly byte[] Uid = Convert.FromHexString("04A1B2C3D4E5F6");
    private const uint Aid = 0x123456;

    [Theory]
    [InlineData(NxpscCmdSet.NativeIso)]
    [InlineData(NxpscCmdSet.Native)]
    public void Personalise_an_application_key_and_prove_it(NxpscCmdSet cmdSet)
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        using var newKey = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), 1);
        mock.SetChangeKeyResult(newKey);

        using var card = NxpscCard.Open(mock, cmdSet);
        Assert.Equal(cmdSet, card.CmdSet);

        var version = card.GetVersion();
        Assert.Equal(Uid, version.Uid);
        Assert.Equal(0x33, version.HwMajor);
        Assert.Equal(NxpscCardType.DesfireEv3, card.Identify());
        Assert.Equal(NxpscCardType.DesfireEv3, card.CardType);

        using (var picc = NxpscKey.FactoryPiccMasterKey())
        {
            card.SelectApplication(0);
            card.Authenticate(0, picc);
        }
        Assert.True(card.IsAuthenticated);
        Assert.Equal(Uid, card.GetCardUid());

        card.CreateApplication(Aid, 0x0B, 1, NxpscKeyType.Aes128);
        Assert.True(mock.HasApplication(Aid));

        card.SelectApplication(Aid);
        Assert.Equal(Aid, card.SelectedAid);
        using (var factory = NxpscKey.FactoryAesApplicationKey())
        {
            card.Authenticate(0, factory);
            card.ChangeKey(0, factory, newKey);
        }
        Assert.True(mock.KeyEquals(Aid, 0, newKey));

        card.SelectApplication(Aid);
        card.Authenticate(0, newKey);
        Assert.True(card.IsAuthenticated);
    }

    /// <summary>
    /// The card describes itself from what was created on it, not from a
    /// fixture: an application's settings, its key count and its key versions
    /// are the ones that were asked for.
    /// </summary>
    [Fact]
    public void The_card_describes_the_application_it_was_given()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        using var newKey = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), 7);
        mock.SetChangeKeyResult(newKey);

        using var card = NxpscCard.Open(mock);
        card.GetVersion();
        card.Identify();
        using (var picc = NxpscKey.FactoryPiccMasterKey())
        {
            card.SelectApplication(0);
            card.Authenticate(0, picc);
        }
        card.CreateApplication(Aid, 0x0B, 6, NxpscKeyType.Aes128);
        Assert.Equal([Aid], card.GetApplicationIds());

        card.SelectApplication(Aid);
        var settings = card.GetKeySettings();
        Assert.Equal(0x0B, settings.Settings);
        Assert.Equal(6, settings.NumKeys);
        Assert.Equal(NxpscKeyType.Aes128, settings.KeyType);

        // every key starts at the factory version, and takes the new key's
        // version once it has been changed
        Assert.Equal(0, card.GetKeyVersion(0));
        using (var factory = NxpscKey.FactoryAesApplicationKey())
        {
            card.Authenticate(0, factory);
            card.ChangeKey(0, factory, newKey);
        }
        card.SelectApplication(Aid);
        Assert.Equal(7, card.GetKeyVersion(0));

        // a key the application does not have is an error, not a number
        Assert.Throws<NxpscException>(() => card.GetKeyVersion(9));
    }

    [Fact]
    public void A_wrong_key_fails_authentication()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        mock.AddApplication(Aid, NxpscKeyType.Aes128, 1);
        using var card = NxpscCard.Open(mock);
        using var wrong = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("0102030405060708090A0B0C0D0E0F10"));

        card.SelectApplication(Aid);
        var ex = Assert.ThrowsAny<NxpscException>(() => card.Authenticate(0, wrong));
        Assert.False(ex.IsTransport);
        Assert.False(card.IsAuthenticated);
    }

    [Fact]
    public void An_absent_application_is_a_card_status_not_a_transport_failure()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        using var card = NxpscCard.Open(mock);

        var ex = Assert.Throws<NxpscException>(() => card.SelectApplication(0xABCDEF));
        Assert.True(ex.IsCardStatus(DesfireStatus.ApplicationNotFound));
        Assert.Equal(DesfireStatus.ApplicationNotFound, card.LastStatus);
    }

    [Fact]
    public void Reads_come_back_through_the_callback()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        var signature = Enumerable.Range(0, 56).Select(i => (byte)i).ToArray();
        mock.SetSignature(signature);
        using var card = NxpscCard.Open(mock);

        Assert.Equal(signature, card.GetSignature());
        Assert.True(card.GetFreeMemory() > 0);

        // the card answers about what it holds, so give it an application
        card.CreateApplication(Aid, 0x0B, 3, NxpscKeyType.Aes128);
        Assert.Equal([Aid], card.GetApplicationIds());

        card.SelectApplication(Aid);
        var settings = card.GetKeySettings();
        Assert.InRange(settings.NumKeys, 1, 14);
        _ = card.GetKeyVersion(0);
    }

    [Fact]
    public void A_torn_field_is_a_transport_failure()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        mock.TearOn(0x60, afterExecute: false);     // GetVersion
        using var card = NxpscCard.Open(mock);

        var ex = Assert.Throws<NxpscException>(() => card.GetVersion());
        Assert.True(ex.IsTransport);
        Assert.True(mock.Torn);

        mock.Reinsert();
        Assert.Equal(Uid, card.GetVersion().Uid);
    }

    [Fact]
    public void Once_the_mock_is_in_use_a_real_transport_is_refused()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        using var real = new NotAMock();

        Assert.Throws<InvalidOperationException>(() => NxpscCard.Open(real));
        Assert.Equal(0, real.Calls);
    }

    [Fact]
    public void A_disposed_card_refuses_further_calls()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        var card = NxpscCard.Open(mock);
        card.Dispose();
        Assert.Throws<ObjectDisposedException>(() => card.GetVersion());
    }

    private sealed class NotAMock : ICardTransport
    {
        public int Calls { get; private set; }
        public string Description => "not a mock";

        public bool TryTransceive(ReadOnlySpan<byte> command, Span<byte> response, out int responseLength)
        {
            Calls++;
            responseLength = 0;
            return false;
        }

        public void Dispose()
        {
        }
    }
}
