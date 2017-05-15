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

Task("Default")
    .IsDependentOn("Clean")
    .IsDependentOn("Restore")
    .IsDependentOn("Build");

var target = Argument("target", "Default");
RunTarget(target);