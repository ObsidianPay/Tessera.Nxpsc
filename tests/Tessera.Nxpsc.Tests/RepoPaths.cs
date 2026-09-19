namespace Tessera.Nxpsc.Tests;

/// <summary>Files of this repository the tests read: libnxpsc's header and the native build output.</summary>
internal static class RepoPaths
{
    public static string Root { get; } = FindRoot();

    public static string Header => Path.Combine(Root, "external", "libnxpsc", "include", "nxpsc", "nxpsc.h");

    public static string NativeOut => Path.Combine(Root, "native", "build", "out");

    public static string LayoutProbe =>
        Path.Combine(NativeOut, OperatingSystem.IsWindows() ? "layout_probe.exe" : "layout_probe");

    private static string FindRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Tessera.Nxpsc.sln")))
                return dir.FullName;
        }
        throw new InvalidOperationException("Run the tests from inside the Tessera.Nxpsc repository.");
    }
}
