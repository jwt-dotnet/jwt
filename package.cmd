set path=%PATH%;C:\Program Files (x86)\MSBuild\14.0\Bin\;
set path=%PATH%;C:\Program Files (x86)\NuGet\;

if not exist package mkdir package
if not exist package\lib mkdir package\lib
if not exist package\lib\net35 mkdir package\lib\net35

msbuild JWT.sln -p:Configuration=Release
copy src\JWT\bin\Release\JWT.dll package\lib\net35

nuget pack JWT.nuspec -BasePath package

pause