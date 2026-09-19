using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Tessera.Nxpsc.Native;

namespace Tessera.Nxpsc.Tests;

/// <summary>
/// The binding matches the library it loads: every public function declared
/// and exported, every struct laid out the way the C compiler lays it out.
/// </summary>
public partial class BindingTests
{
    private static readonly Dictionary<string, Type> Mirrors = new()
    {
        ["nxpsc_key_t"] = typeof(NativeKey),
        ["nxpsc_transport_t"] = typeof(NativeTransport),
        ["nxpsc_version_t"] = typeof(NativeVersion),
        ["nxpsc_access_t"] = typeof(NativeAccess),
        ["nxpsc_file_settings_t"] = typeof(NativeFileSettings),
        ["nxpsc_app_t"] = typeof(NativeApp),
        ["nxpsc_app_config_t"] = typeof(NativeAppConfig),
        ["nxpsc_delegate_info_t"] = typeof(NativeDelegateInfo),
        ["nxpsc_picc_config_t"] = typeof(NativePiccConfig),
        ["nxpsc_sdm_settings_t"] = typeof(NativeSdmSettings),
    };

    private static IEnumerable<string> DeclaredEntryPoints() =>
        typeof(NxpscNative).GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(m => m.GetCustomAttribute<DllImportAttribute>() is not null)
            .Select(m => m.Name);

    private static HashSet<string> HeaderFunctions()
    {
        var text = CommentPattern().Replace(File.ReadAllText(RepoPaths.Header), "");
        return FunctionPattern().Matches(text).Select(m => m.Groups[1].Value).ToHashSet();
    }

    [Fact]
    public void Every_function_in_nxpsc_h_is_declared()
    {
        var header = HeaderFunctions();
        Assert.True(header.Count > 100, $"parsed only {header.Count} functions from nxpsc.h");

        var missing = header.Except(DeclaredEntryPoints()).Order().ToList();
        Assert.True(missing.Count == 0, "not bound: " + string.Join(", ", missing));
    }

    [Fact]
    public void Nothing_is_declared_that_nxpsc_h_does_not_have_except_the_mock_rng_hook()
    {
        var extra = DeclaredEntryPoints().Except(HeaderFunctions()).ToList();
        Assert.Equal(["nxpsc_set_rng"], extra);
    }

    /// <summary>
    /// Every declared function is exported by the library that loads. An MSVC
    /// libnxpsc once shipped with an empty export table; this is what catches it.
    /// </summary>
    [Fact]
    public void Every_declared_function_is_exported_by_the_loaded_library()
    {
        Assert.True(NxpscLibrary.SelfTest());      // loads the library through the normal resolver
        var handle = NativeLibrary.Load(NxpscNative.Library, typeof(NxpscNative).Assembly, null);

        var missing = DeclaredEntryPoints().Where(name => !NativeLibrary.TryGetExport(handle, name, out _)).ToList();
        Assert.True(missing.Count == 0, "not exported: " + string.Join(", ", missing));
    }

    [Fact]
    public void Every_struct_mirror_matches_the_c_compiler_layout()
    {
        Assert.True(File.Exists(RepoPaths.LayoutProbe),
            $"{RepoPaths.LayoutProbe} is missing: build native/ first (see README).");

        using var probe = Process.Start(new ProcessStartInfo(RepoPaths.LayoutProbe)
        {
            RedirectStandardOutput = true,
            UseShellExecute = false,
        })!;
        var lines = probe.StandardOutput.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        probe.WaitForExit();

        var problems = new List<string>();
        var checkedStructs = new HashSet<string>();
        foreach (var line in lines)
        {
            var parts = line.Split(' ');
            var expected = int.Parse(parts[2]);
            if (parts[1] == "size")
            {
                var type = Mirrors[parts[0]];
                checkedStructs.Add(parts[0]);
                var actual = Marshal.SizeOf(type);
                if (actual != expected)
                    problems.Add($"{parts[0]}: C size {expected}, managed {actual}");
            }
            else
            {
                var dot = parts[0].IndexOf('.');
                var type = Mirrors[parts[0][..dot]];
                var field = Pascal(parts[0][(dot + 1)..]);
                var actual = (int)Marshal.OffsetOf(type, field);
                if (actual != expected)
                    problems.Add($"{parts[0]}: C offset {expected}, managed {type.Name}.{field} at {actual}");
            }
        }

        Assert.Equal(Mirrors.Keys.Order(), checkedStructs.Order());
        Assert.True(problems.Count == 0, string.Join("\n", problems));
    }

    private static string Pascal(string snake) =>
        string.Concat(snake.Split('_').Select(p => char.ToUpperInvariant(p[0]) + p[1..]));

    [GeneratedRegex(@"//[^\n]*")]
    private static partial Regex CommentPattern();

    [GeneratedRegex(@"\b(nxpsc_[a-z0-9_]+)\s*\([^;{]*\)\s*;")]
    private static partial Regex FunctionPattern();
}
