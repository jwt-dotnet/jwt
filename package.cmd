tools\nuget.exe update -self

if not exist package mkdir package
if not exist package mkdir package
if not exist package\lib mkdir package\lib
if not exist package\lib\3.5 mkdir package\lib\3.5

copy JWT\bin\Release\JWT.dll package\lib\3.5\

tools\nuget.exe pack JWT.nuspec -BasePath package