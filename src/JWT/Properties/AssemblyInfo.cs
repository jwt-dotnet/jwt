using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("JWT.Tests.Common, PublicKey=" + AssemblyInfo.PublicKey)]
[assembly: InternalsVisibleTo("JWT.Tests.NetCore2, PublicKey=" + AssemblyInfo.PublicKey)]
[assembly: InternalsVisibleTo("JWT.Tests.NetCore3, PublicKey=" + AssemblyInfo.PublicKey)]
[assembly: InternalsVisibleTo("JWT.Tests.Net35, PublicKey=" + AssemblyInfo.PublicKey)]
[assembly: InternalsVisibleTo("JWT.Tests.Net40, PublicKey=" + AssemblyInfo.PublicKey)]
[assembly: InternalsVisibleTo("JWT.Tests.Net46, PublicKey=" + AssemblyInfo.PublicKey)]
[assembly: InternalsVisibleTo("JWT.Tests.Net50, PublicKey=" + AssemblyInfo.PublicKey)]

internal static class AssemblyInfo
{
    public const string PublicKey = "002400000480000094000000060200000024000052534131000400000100010041e599bf147c55b2d243a92f3b81b003a113abc6ce6c8423d3b5f41f807471d6acf45675ac5924e69d04fb76b58cd2985eb47e3408f5f20b913e2dfd8074edab55b62b1b2f2b6538af885f979acb1b2a80eb64da7f097b9788390833ed7d974f7abf6d53cbec49abc4d95e999fbb8ee626c50d3f1c3c750bb82ea5e23233dfd7";
}
