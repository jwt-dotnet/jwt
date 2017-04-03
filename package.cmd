tools\nuget.exe update -self

if not exist package mkdir package
if not exist package mkdir package
if not exist package\lib mkdir package\lib
if not exist package\lib\net35 mkdir package\lib\net35

msbuild src\JWT.sln -p:Configuration=Release
copy src\JWT\bin\Release\JWT.dll package\lib\net35

tools\nuget.exe pack JWT.nuspec -BasePath package