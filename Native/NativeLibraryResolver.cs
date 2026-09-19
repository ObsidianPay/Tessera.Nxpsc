using System.Reflection;
using System.Runtime.InteropServices;

namespace Tessera.Nxpsc.Native;

/// <summary>
/// Where the native libraries come from. TESSERA_NXPSC_DIR, when set, wins;
/// otherwise the default probing applies (the tool's own directory, where the
/// build copies them, then the system search path).
/// </summary>
internal static class NativeLibraryResolver
{
    public const string DirectoryVariable = "TESSERA_NXPSC_DIR";

    private static int _registered;

    /// <summary>
    /// Idempotent. Called from the static constructors of NxpscCard and MockCard,
    /// the only types that P/Invoke, so it runs before the first native call.
    /// </summary>
    public static void EnsureRegistered()
    {
        if (Interlocked.Exchange(ref _registered, 1) == 0)
            NativeLibrary.SetDllImportResolver(typeof(NativeLibraryResolver).Assembly, Resolve);
    }

    private static nint Resolve(string name, Assembly assembly, DllImportSearchPath? searchPath)
    {
        var directory = Environment.GetEnvironmentVariable(DirectoryVariable);
        if (string.IsNullOrWhiteSpace(directory))
            return 0;

        foreach (var file in Candidates(name))
        {
            var path = Path.Combine(directory, file);
            if (File.Exists(path) && NativeLibrary.TryLoad(path, out var handle))
                return handle;
        }
        return 0;
    }

    private static IEnumerable<string> Candidates(string name)
    {
        if (OperatingSystem.IsWindows())
        {
            yield return name + ".dll";
            yield return "lib" + name + ".dll";     // a MinGW build
        }
        else if (OperatingSystem.IsMacOS())
        {
            yield return "lib" + name + ".dylib";
            yield return name + ".dylib";
        }
        else
        {
            yield return "lib" + name + ".so";
            yield return name + ".so";
        }
    }

    /// <summary>A one-line hint for the "library not found" message.</summary>
    public static string MissingLibraryHint(string name) =>
        $"{name} was not found next to the tool or in {DirectoryVariable}. " +
        "Build it as described in docs/building-libnxpsc.md.";
}
