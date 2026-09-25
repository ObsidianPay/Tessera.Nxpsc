using Tessera.Nxpsc.Mock;

namespace Tessera.Nxpsc.Tests;

/// <summary>
/// The transaction MAC through the binding: a record written to the card, the
/// commit that returns the card's counter and MAC, and the same MAC recomputed
/// on the host from the record alone. The card side is libnxpsc's mock, whose
/// TMAC implementation is written independently of the one being checked.
/// </summary>
public class TransactionMacTests
{
    private static readonly byte[] Uid = Convert.FromHexString("04A1B2C3D4E5F6");
    private const uint Aid = 0x123456;
    private const byte RecordFile = 0x01;
    private const byte TmacFile = 0x02;

    private static readonly byte[] Record =
    [
        0x01, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
        0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    /// <summary>Opens the card, creates the application and its TMAC file, and authenticates.</summary>
    private static NxpscCard Ready(MockCard mock, NxpscKey appKey, NxpscKey tmKey)
    {
        mock.SetTransactionMacKey(tmKey);
        mock.SetChangeKeyResult(appKey);

        var card = NxpscCard.Open(mock);
        card.GetVersion();      // the library frames later commands by card type
        card.Identify();
        using (var picc = NxpscKey.FactoryPiccMasterKey())
        {
            card.SelectApplication(0);
            card.Authenticate(0, picc);
        }
        card.CreateApplication(Aid, 0x0B, 3, NxpscKeyType.Aes128);
        card.SelectApplication(Aid);
        using (var factory = NxpscKey.FactoryAesApplicationKey())
        {
            card.Authenticate(0, factory);
            card.ChangeKey(0, factory, appKey);
        }
        card.SelectApplication(Aid);
        card.Authenticate(0, appKey);

        // ReadWrite 0x0F: CommitReaderID stays disabled
        card.CreateTransactionMacFile(TmacFile, NxpscCommMode.Mac,
            new NxpscAccessRights(2, 0x0F, 0x0F, 0), tmKey, 1);
        card.CreateRecordFile(RecordFile, cyclic: true, NxpscCommMode.Mac, new NxpscAccessRights(2, 2, 2, 0), 32, 4);
        return card;
    }

    [Fact]
    public void A_committed_transaction_returns_a_mac_the_host_can_recompute()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        using var appKey = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), 1);
        using var tmKey = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"), 1);
        using var card = Ready(mock, appKey, tmKey);

        card.WriteRecord(RecordFile, 0, Record, NxpscCommMode.Mac);
        var mac = card.CommitTransactionWithMac();

        Assert.Equal(4, mac.Tmc.Length);
        Assert.Equal(8, mac.Tmv.Length);
        Assert.Equal(1u, mac.Counter);
        Assert.Equal(1u, mock.TransactionCounter);

        var tmi = NxpscTmac.BuildWriteRecordTmi(RecordFile, 0, Record);
        Assert.Equal(16 + 32, tmi.Length);
        Assert.Equal(NxpscTmac.Compute(tmKey, Uid, mac.Tmc, tmi), mac.Tmv);
        Assert.True(NxpscTmac.Verify(tmKey, Uid, mac, tmi));
    }

    [Fact]
    public void The_counter_moves_and_the_value_with_it()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        using var appKey = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), 1);
        using var tmKey = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"), 1);
        using var card = Ready(mock, appKey, tmKey);
        var tmi = NxpscTmac.BuildWriteRecordTmi(RecordFile, 0, Record);

        card.WriteRecord(RecordFile, 0, Record, NxpscCommMode.Mac);
        var first = card.CommitTransactionWithMac();
        card.WriteRecord(RecordFile, 0, Record, NxpscCommMode.Mac);
        var second = card.CommitTransactionWithMac();

        Assert.Equal(1u, first.Counter);
        Assert.Equal(2u, second.Counter);
        // the same record twice, and still not the same MAC: replay is visible
        Assert.NotEqual(first.Tmv, second.Tmv);
        Assert.True(NxpscTmac.Verify(tmKey, Uid, second, tmi));
        // the older value does not pass under the newer counter
        Assert.False(NxpscTmac.Verify(tmKey, Uid, new TransactionMac(second.Tmc, first.Tmv), tmi));
    }

    [Fact]
    public void A_wrong_key_or_a_different_record_does_not_verify()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        using var appKey = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), 1);
        using var tmKey = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"), 1);
        using var card = Ready(mock, appKey, tmKey);

        card.WriteRecord(RecordFile, 0, Record, NxpscCommMode.Mac);
        var mac = card.CommitTransactionWithMac();

        var tmi = NxpscTmac.BuildWriteRecordTmi(RecordFile, 0, Record);
        using var wrongKey = new NxpscKey(NxpscKeyType.Aes128, new byte[16], 1);
        Assert.False(NxpscTmac.Verify(wrongKey, Uid, mac, tmi));

        var tampered = (byte[])Record.Clone();
        tampered[20] ^= 0x01;   // a terminal reporting a different amount
        Assert.False(NxpscTmac.Verify(tmKey, Uid, mac,
            NxpscTmac.BuildWriteRecordTmi(RecordFile, 0, tampered)));

        // a different card's UID gives a different session key
        Assert.False(NxpscTmac.Verify(tmKey, Convert.FromHexString("04000000000000"), mac, tmi));
    }

    [Fact]
    public void The_transaction_mac_input_is_the_layout_the_card_accumulates()
    {
        var tmi = NxpscTmac.BuildWriteRecordTmi(0x05, 0, Record);

        Assert.Equal(0x3B, tmi[0]);                     // WriteRecord
        Assert.Equal(0x05, tmi[1]);                     // file
        Assert.Equal(new byte[] { 0, 0, 0 }, tmi[2..5]);        // offset, LSB first
        Assert.Equal(new byte[] { 0x20, 0, 0 }, tmi[5..8]);     // length, LSB first
        Assert.Equal(new byte[8], tmi[8..16]);                  // the zero padding
        Assert.Equal(Record, tmi[16..]);
    }

    [Fact]
    public void Arguments_are_checked()
    {
        using var tmKey = new NxpscKey(NxpscKeyType.Aes128, new byte[16], 1);
        var tmi = NxpscTmac.BuildWriteRecordTmi(RecordFile, 0, Record);

        Assert.Throws<ArgumentException>(() => NxpscTmac.Compute(tmKey, Uid, new byte[3], tmi));
        Assert.Throws<ArgumentNullException>(() => NxpscTmac.Compute(null!, Uid, new byte[4], tmi));
        // a 7 byte UID and whole blocks of input, both refused by the library
        Assert.Throws<NxpscException>(() => NxpscTmac.Compute(tmKey, new byte[4], new byte[4], tmi));
        Assert.Throws<NxpscException>(() => NxpscTmac.Compute(tmKey, Uid, new byte[4], new byte[8]));
    }

    /// <summary>
    /// A caller that reads its own file settings back gets what it asked for,
    /// which is the only way a personalisation station can catch a wrong access
    /// nibble before the card leaves the bench.
    /// </summary>
    [Fact]
    public void Files_are_reported_as_they_were_created()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        using var appKey = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), 1);
        using var tmKey = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("A0A1A2A3A4A5A6A7A8A9AAABACADAEAF"), 1);
        mock.SetTransactionMacFileSettings(TmacFile, NxpscCommMode.Mac, new NxpscAccessRights(2, 0x0F, 0x0F, 0));
        using var card = Ready(mock, appKey, tmKey);

        var access = new NxpscAccessRights(2, 2, 2, 0);
        Assert.Equal([RecordFile, TmacFile], card.GetFileIds().Order());

        var record = card.GetFileSettings(RecordFile);
        Assert.Equal(NxpscFileType.CyclicRecord, record.Type);
        Assert.Equal(NxpscCommMode.Mac, record.CommMode);
        Assert.Equal(access, record.Access);
        Assert.Equal(32u, record.RecordSize);
        Assert.Equal(4u, record.MaxRecords);

        // the transaction MAC file's settings travel enciphered, so the mock is
        // told them; on a card they are read off the silicon
        var tmac = card.GetFileSettings(TmacFile);
        Assert.Equal(NxpscFileType.TransactionMac, tmac.Type);
        Assert.Equal(new NxpscAccessRights(2, 0x0F, 0x0F, 0), tmac.Access);
    }

    /// <summary>A card an earlier run already finished, files and all.</summary>
    [Fact]
    public void A_card_can_start_with_files_already_on_it()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        mock.AddFile(RecordFile, NxpscFileType.CyclicRecord, NxpscCommMode.Mac,
            new NxpscAccessRights(2, 2, 2, 0), recordSize: 32, maxRecords: 4);
        mock.AddFile(TmacFile, NxpscFileType.TransactionMac, NxpscCommMode.Mac,
            new NxpscAccessRights(2, 0x0F, 0x0F, 0));
        mock.EnableTransactionMac();

        using var card = NxpscCard.Open(mock);
        card.GetVersion();
        card.Identify();

        Assert.Equal([RecordFile, TmacFile], card.GetFileIds().Order());
        Assert.Equal(32u, card.GetFileSettings(RecordFile).RecordSize);
    }

    [Fact]
    public void Without_a_transaction_mac_file_the_card_refuses_the_option()
    {
        using var mock = new MockCard(NxpscCardType.DesfireEv3, Uid);
        using var appKey = new NxpscKey(NxpscKeyType.Aes128, Convert.FromHexString("00112233445566778899AABBCCDDEEFF"), 1);
        mock.SetChangeKeyResult(appKey);

        using var card = NxpscCard.Open(mock);
        card.GetVersion();
        card.Identify();
        using (var picc = NxpscKey.FactoryPiccMasterKey())
        {
            card.SelectApplication(0);
            card.Authenticate(0, picc);
        }
        card.CreateApplication(Aid, 0x0B, 3, NxpscKeyType.Aes128);
        card.SelectApplication(Aid);
        using (var factory = NxpscKey.FactoryAesApplicationKey())
            card.Authenticate(0, factory);
        card.CreateRecordFile(RecordFile, cyclic: true, NxpscCommMode.Mac, new NxpscAccessRights(2, 2, 2, 0), 32, 4);

        card.WriteRecord(RecordFile, 0, Record, NxpscCommMode.Mac);
        Assert.Throws<NxpscException>(() => card.CommitTransactionWithMac());
    }
}
