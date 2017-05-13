#tool "nuget:?package=xunit.runner.console"

var configuration = Argument("configuration", "Release");

Task("Clean")
.Does(() =>
{
    CleanDirectory("./artifacts/");
});

Task("Restore")
.Does(() => 
{
    DotNetCoreRestore();
});

Task("Build")
.Does(() =>
{
    var projects = GetFiles("./src/**/*.csproj");
    Console.WriteLine("Building {0} projects", projects.Count());

    foreach (var project in projects)
    {
        DotNetCoreBuild(project.FullPath, new DotNetCoreBuildSettings
        {
            Configuration = configuration
        });
    }
});

Task("Pack")
.Does(() =>
{
    var projects = GetFiles("./src/**/*.csproj");
    Console.WriteLine("Packing {0} projects", projects.Count());

    foreach (var project in projects)
    {
        DotNetCorePack(project.FullPath, new DotNetCorePackSettings
        {
            Configuration = configuration,
            OutputDirectory = "./artifacts/"
        });
    }
});

Task("Test")
.IsDependentOn("TestCore")
.IsDependentOn("TestNetFramework");

Task("TestCore")
.IsDependentOn("Restore")
.IsDependentOn("Build")
.Does(() =>
{
    var coreTestProject = "JWT.Tests.Core";
    Console.WriteLine("Running tests in {0}", coreTestProject);
    DotNetCoreTest(string.Format("./tests/{0}/{0}.csproj", coreTestProject));
});

Task("TestNetFramework")
.Does(() =>
{
    var frameworkTestProject = "JWT.Tests.NETFramework";
    Console.WriteLine("Running tests in {0}", frameworkTestProject);

    NuGetRestore(
      string.Format("./tests/{0}/{0}.csproj", frameworkTestProject),
      new NuGetRestoreSettings { PackagesDirectory = string.Format("./packages/", frameworkTestProject) });
    
    MSBuild(
      string.Format("./tests/{0}/{0}.csproj", frameworkTestProject),
      new MSBuildSettings { Configuration = "Release" });

    XUnit2(string.Format("./tests/{0}/bin/Release/{0}.dll", frameworkTestProject));
});

Task("Default")
    .IsDependentOn("Clean")
    .IsDependentOn("Restore")
    .IsDependentOn("Build")
    .IsDependentOn("Pack");


var target = Argument("target", "Default");
RunTarget(target);