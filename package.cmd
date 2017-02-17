tools\nuget.exe update -self

if not exist package mkdir package
if not exist package mkdir package
if not exist package\lib mkdir package\lib
if not exist package\lib\net45 mkdir package\lib\net45

msbuild src\JWT.sln -p:Configuration=Release
copy src\JWT\bin\Release\JWT.dll package\lib\net45

tools\nuget.exe pack JWT.nuspec -BasePath package