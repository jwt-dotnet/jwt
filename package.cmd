if not exist download mkdir download
if not exist download\package mkdir download\package
if not exist download\package\lib mkdir download\package\lib
if not exist download\package\lib\3.5 mkdir download\package\lib\3.5

copy JWT\bin\Release\*.dll download
copy LICENSE.txt download

copy JWT\bin\Release\JWT.dll download\package\lib\3.5\

tools\nuget.exe pack JWT.nuspec -b download\package -o download