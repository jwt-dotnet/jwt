var configuration = Argument("configuration", "Release");

Task("Clean")
.Does(() =>
{
    CleanDirectories(string.Format("./**/obj/{0}/", configuration));
    CleanDirectories(string.Format("./**/bin/{0}/", configuration));
});

Task("Restore")
.Does(() => 
{
    NuGetRestore("./Jwt.sln");
});

Task("Build")
.Does(() =>
{
    MSBuild("./Jwt.sln", settings => settings.SetConfiguration(configuration));
});

Task("Test")
.IsDependentOn("Restore")
.IsDependentOn("Build")
.Does(() =>
{
    XUnit2(string.Format("./tests/**/bin/{0}/*.Tests.dll", configuration), new XUnit2Settings { ToolPath = "./packages/xunit.runner.console.2.2.0/tools/xunit.console.x86.exe" });
});

Task("Pack")
.IsDependentOn("Build")
.Does(() =>
{
// copy src\JWT\bin\Release\JWT.dll package\lib\net35

// nuget pack JWT.nuspec -BasePath package

    CreateDirectory("./package.tmp/lib/net35");
    CopyFile("./src/JWT/bin/Release/JWT.dll", "./package.tmp/lib/net35/JWT.dll");

    NuGetPack("./JWT.nuspec", new NuGetPackSettings
    {
        BasePath = "./package.tmp",
        OutputDirectory = "./artifacts"
    });
});

Task("Default")
    .IsDependentOn("Clean")
    .IsDependentOn("Restore")
    .IsDependentOn("Build")
    .IsDependentOn("Pack");

var target = Argument("target", "Default");
RunTarget(target);
