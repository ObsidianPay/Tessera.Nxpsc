namespace Tessera.Nxpsc.Tests;

/// <summary>The functions that need no card, checked against published or libnxpsc's own vectors.</summary>
public class LibraryTests
{
    [Fact]
    public void Self_test_passes_and_the_version_is_reported()
    {
        Assert.True(NxpscLibrary.SelfTest());
        Assert.Matches(@"^\d+\.\d+\.\d+$", NxpscLibrary.LibraryVersion);
    }

    // AN10922's published examples, as in libnxpsc's src/nxpsc_selftest.c
    private const string Input = "04782E21801D803042F54E585020416275";

    [Theory]
    [InlineData(NxpscKeyType.Aes128, "00112233445566778899AABBCCDDEEFF", 17, "A8DD63A3B89D54B37CA802473FDA9175")]
    [InlineData(NxpscKeyType.TwoKey3Des, "00112233445566778899AABBCCDDEEFF", 15, "16F8597C9E8910C86B9648D006107DD7")]
    [InlineData(NxpscKeyType.ThreeKey3Des, "00112233445566778899AABBCCDDEEFF0102030405060708", 13,
        "2F0DD03675D3FB9A5705AB0BDA91CA0B55B8E07FCDBF10EC")]
    public void An10922_published_vectors_round_trip_through_the_binding(NxpscKeyType type, string master, int inputLength, string expected)
    {
        using var key = new NxpscKey(type, Convert.FromHexString(master));
        using var derived = NxpscLibrary.DiversifyAn10922(key, Convert.FromHexString(Input)[..inputLength], derivedVersion: 7);

        Assert.Equal(type, derived.Type);
        Assert.Equal(7, derived.Version);
        Assert.Equal(expected, Convert.ToHexString(derived.Bytes));
    }

    [Fact]
    public void Diversification_input_over_31_bytes_is_refused()
    {
        using var key = new NxpscKey(NxpscKeyType.Aes128, new byte[16]);
        var ex = Assert.Throws<NxpscException>(() => NxpscLibrary.DiversifyAn10922(key, new byte[32]));
        Assert.Equal(NxpscErrorCode.Length, ex.Code);
    }

    [Fact]
    public void Access_rights_pack_as_read_write_readwrite_change_nibbles()
    {
        var access = new NxpscAccessRights(0x0A, 0x0B, 0x0C, 0x0D);
        Assert.Equal(0xABCD, access.Pack());
        Assert.Equal(access, NxpscAccessRights.Unpack(0xABCD));
        Assert.Equal(new NxpscAccessRights(NxpscAccessRights.Free, 0, 1, NxpscAccessRights.Denied), NxpscAccessRights.Unpack(0xE01F));
    }

    /// <summary>AN12196's NTAG 424 DNA example, as libnxpsc's own protocol test builds it.</summary>
    [Fact]
    public void Sdm_settings_build_the_an12196_example_payload()
    {
        var access = new NxpscAccessRights(NxpscAccessRights.Free, 0, 0, 0);
        var sdm = new NxpscSdmSettings
        {
            Enabled = true,
            UidMirror = true,
            CounterMirror = true,
            MetaReadKey = 0x0E,
            FileReadKey = 0x02,
            CounterRetKey = 0x0F,
            UidOffset = 0x20,
            CounterOffset = 0x43,
            MacInputOffset = 0x43,
            MacOffset = 0x4F,
        };

        var payload = NxpscLibrary.BuildSdmSettings(NxpscCommMode.Plain, access, sdm);

        Assert.Equal(6 + 4 * 3, payload.Length);
        Assert.Equal(0x40, payload[0]);
        Assert.Equal([0x00, 0xE0], payload[1..3]);
        Assert.Equal(0xC1, payload[3]);
        Assert.Equal([0xFF, 0xE2], payload[4..6]);
        Assert.Equal([0x20, 0x00, 0x00], payload[6..9]);
        Assert.Equal(0x43, payload[9]);
        Assert.Equal(0x4F, payload[15]);

        // SDM disabled leaves only the file option and the access rights
        var disabled = NxpscLibrary.BuildSdmSettings(NxpscCommMode.Full, access, sdm with { Enabled = false });
        Assert.Equal(3, disabled.Length);
        Assert.Equal(0x03, disabled[0]);
    }

    [Theory]
    [InlineData(0x01, 0x33, 0x00, NxpscCardType.DesfireEv3)]
    [InlineData(0x01, 0x12, 0x00, NxpscCardType.DesfireEv2)]
    [InlineData(0x04, 0x30, 0x00, NxpscCardType.Ntag424)]
    public void Card_type_comes_from_libnxpsc_s_product_table(byte type, byte major, byte minor, NxpscCardType expected) =>
        Assert.Equal(expected, NxpscLibrary.CardTypeFromVersion(type, major, minor));

    [Fact]
    public void Names_and_sizes_come_from_the_library()
    {
        Assert.Equal(16, NxpscLibrary.KeySize(NxpscKeyType.Aes128));
        Assert.Equal(24, NxpscLibrary.KeySize(NxpscKeyType.ThreeKey3Des));
        Assert.Contains("EV3", NxpscLibrary.CardTypeName(NxpscCardType.DesfireEv3));
        Assert.False(string.IsNullOrWhiteSpace(NxpscLibrary.StatusText(DesfireStatus.AuthenticationError)));
        Assert.False(string.IsNullOrWhiteSpace(NxpscLibrary.KeyTypeName(NxpscKeyType.Aes128)));
        Assert.False(string.IsNullOrWhiteSpace(NxpscLibrary.ErrorText(NxpscErrorCode.Transport)));
    }

    [Fact]
    public void Keys_compare_by_type_and_bytes_not_version()
    {
        using var a = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), 1);
        using var sameBytesOtherVersion = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), 2);
        using var otherBytes = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("00112233445566778899AABBCCDDEEFE"));
        using var otherType = new NxpscKey(NxpscKeyType.TwoKey3Des, Convert.FromHexString("00112233445566778899AABBCCDDEEFF"));

        Assert.True(a.FixedTimeEquals(sameBytesOtherVersion));
        Assert.False(a.FixedTimeEquals(otherBytes));
        Assert.False(a.FixedTimeEquals(otherType));
    }

    [Fact]
    public void Keys_never_render_their_bytes_and_are_zeroed_on_dispose()
    {
        var key = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("DEADBEEFDEADBEEFDEADBEEFDEADBEEF"));
        Assert.DoesNotContain("DEAD", key.ToString(), StringComparison.OrdinalIgnoreCase);

        using var copy = key.Copy();
        key.Dispose();
        Assert.Throws<ObjectDisposedException>(() => key.Bytes.ToArray());
        Assert.Equal("DEADBEEFDEADBEEFDEADBEEFDEADBEEF", Convert.ToHexString(copy.Bytes));
    }
}
