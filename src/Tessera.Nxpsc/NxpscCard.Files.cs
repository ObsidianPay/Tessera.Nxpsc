using Tessera.Nxpsc.Native;

namespace Tessera.Nxpsc;

// Files, values, records and transactions inside the selected application.
public sealed unsafe partial class NxpscCard
{
    public byte[] GetFileIds() =>
        ReadBuffer(NxpscLimits.MaxFiles, (p, cap, len) => NxpscNative.nxpsc_get_file_ids(Handle, p, cap, len));

    public ushort[] GetIsoFileIds()
    {
        var ids = new ushort[NxpscLimits.MaxFiles];
        nuint count = 0;
        fixed (ushort* p = ids)
            Check(NxpscNative.nxpsc_get_iso_file_ids(Handle, p, (nuint)ids.Length, &count));
        return ids[..(int)count];
    }

    public NxpscFileSettings GetFileSettings(byte fileNo)
    {
        NativeFileSettings settings = default;
        Check(NxpscNative.nxpsc_get_file_settings(Handle, fileNo, &settings));
        return Interop.FromNative(settings);
    }

    public void ChangeFileSettings(byte fileNo, NxpscCommMode comm, NxpscAccessRights access)
    {
        var a = Interop.ToNative(access);
        Check(NxpscNative.nxpsc_change_file_settings(Handle, fileNo, (int)comm, &a));
    }

    /// <summary>ChangeFileSettings with a raw payload (SDM and other vendor specific settings).</summary>
    public void ChangeFileSettings(byte fileNo, ReadOnlySpan<byte> payload)
    {
        fixed (byte* d = payload)
            Check(NxpscNative.nxpsc_change_file_settings_raw(Handle, fileNo, d, (nuint)payload.Length));
    }

    public void CreateStdFile(byte fileNo, NxpscCommMode comm, NxpscAccessRights access, uint size, ushort isoFid = 0)
    {
        var a = Interop.ToNative(access);
        Check(NxpscNative.nxpsc_create_std_file(Handle, fileNo, isoFid, (int)comm, &a, size));
    }

    public void CreateBackupFile(byte fileNo, NxpscCommMode comm, NxpscAccessRights access, uint size, ushort isoFid = 0)
    {
        var a = Interop.ToNative(access);
        Check(NxpscNative.nxpsc_create_backup_file(Handle, fileNo, isoFid, (int)comm, &a, size));
    }

    public void CreateValueFile(byte fileNo, NxpscCommMode comm, NxpscAccessRights access,
        int lowerLimit, int upperLimit, int value, bool limitedCredit)
    {
        var a = Interop.ToNative(access);
        Check(NxpscNative.nxpsc_create_value_file(Handle, fileNo, (int)comm, &a, lowerLimit, upperLimit, value, limitedCredit));
    }

    public void CreateRecordFile(byte fileNo, bool cyclic, NxpscCommMode comm, NxpscAccessRights access,
        uint recordSize, uint maxRecords, ushort isoFid = 0)
    {
        var a = Interop.ToNative(access);
        Check(NxpscNative.nxpsc_create_record_file(Handle, cyclic, fileNo, isoFid, (int)comm, &a, recordSize, maxRecords));
    }

    public void DeleteFile(byte fileNo) => Check(NxpscNative.nxpsc_delete_file(Handle, fileNo));

    /// <summary>
    /// ReadData. <paramref name="length"/> 0 reads to the end of the file.
    /// Plain comm without a session is allowed when the file's read right is
    /// free; read the file settings first to learn which mode a file expects.
    /// </summary>
    public byte[] ReadData(byte fileNo, uint offset, uint length, NxpscCommMode comm,
        int capacity = NxpscLimits.MaxResponse) =>
        ReadBuffer(capacity, (p, cap, len) =>
            NxpscNative.nxpsc_read_data(Handle, fileNo, offset, length, (int)comm, p, cap, len));

    public void WriteData(byte fileNo, uint offset, ReadOnlySpan<byte> data, NxpscCommMode comm)
    {
        fixed (byte* d = data)
            Check(NxpscNative.nxpsc_write_data(Handle, fileNo, offset, d, (nuint)data.Length, (int)comm));
    }

    public int GetValue(byte fileNo, NxpscCommMode comm)
    {
        int value = 0;
        Check(NxpscNative.nxpsc_get_value(Handle, fileNo, (int)comm, &value));
        return value;
    }

    public void Credit(byte fileNo, int delta, NxpscCommMode comm) =>
        Check(NxpscNative.nxpsc_credit(Handle, fileNo, delta, (int)comm));

    public void LimitedCredit(byte fileNo, int delta, NxpscCommMode comm) =>
        Check(NxpscNative.nxpsc_limited_credit(Handle, fileNo, delta, (int)comm));

    public void Debit(byte fileNo, int delta, NxpscCommMode comm) =>
        Check(NxpscNative.nxpsc_debit(Handle, fileNo, delta, (int)comm));

    public void WriteRecord(byte fileNo, uint offset, ReadOnlySpan<byte> data, NxpscCommMode comm)
    {
        fixed (byte* d = data)
            Check(NxpscNative.nxpsc_write_record(Handle, fileNo, offset, d, (nuint)data.Length, (int)comm));
    }

    /// <summary>Updates part of an existing record; record 0 is the most recent.</summary>
    public void UpdateRecord(byte fileNo, uint recordNo, uint offset, ReadOnlySpan<byte> data, NxpscCommMode comm)
    {
        fixed (byte* d = data)
            Check(NxpscNative.nxpsc_update_record(Handle, fileNo, recordNo, offset, d, (nuint)data.Length, (int)comm));
    }

    /// <summary>ReadRecords, oldest first. <paramref name="recordCount"/> 0 reads them all.</summary>
    public byte[] ReadRecords(byte fileNo, uint recordNo, uint recordCount, NxpscCommMode comm,
        int capacity = NxpscLimits.MaxResponse) =>
        ReadBuffer(capacity, (p, cap, len) =>
            NxpscNative.nxpsc_read_records(Handle, fileNo, recordNo, recordCount, (int)comm, p, cap, len));

    public void ClearRecordFile(byte fileNo) => Check(NxpscNative.nxpsc_clear_record_file(Handle, fileNo));

    public void CommitTransaction() => Check(NxpscNative.nxpsc_commit_transaction(Handle));

    public void AbortTransaction() => Check(NxpscNative.nxpsc_abort_transaction(Handle));

    /// <summary>
    /// CommitReaderID (EV2 transaction MAC files). Returns the previous reader
    /// id, enciphered.
    /// </summary>
    public byte[] CommitReaderId(ReadOnlySpan<byte> readerId)
    {
        var id = readerId.ToArray();
        return ReadBuffer(64, (p, cap, len) =>
        {
            fixed (byte* r = id)
                return NxpscNative.nxpsc_commit_reader_id(Handle, r, (nuint)id.Length, p, cap, len);
        });
    }
}
