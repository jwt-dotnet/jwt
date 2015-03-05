tools\nuget.exe update -self

if not exist package.portable mkdir package.portable
if not exist package.portable mkdir package.portable
if not exist package.portable\lib mkdir package.portable\lib
if not exist package.portable\lib\portable-net403+sl5+netcore45+wp8+MonoAndroid1+MonoTouch1 mkdir "package.portable\lib\portable-net403+sl5+netcore45+wp8+MonoAndroid1+MonoTouch1"

copy "JWT.Portable\bin\Release\JWT.Portable.dll" "package.portable\lib\portable-net403+sl5+netcore45+wp8+MonoAndroid1+MonoTouch1\"

tools\nuget.exe pack JWT.Portable.nuspec -BasePath package.portable