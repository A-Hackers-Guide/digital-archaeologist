$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$exe=Join-Path $root 'build\archaeologist.exe'
if(!(Test-Path $exe)){ throw "Build first: $exe" }
$tmp=Join-Path $env:TEMP 'da-v1-fixture.bin'
[IO.File]::WriteAllBytes($tmp,[byte[]](0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a))
$out=& $exe $tmp
if($LASTEXITCODE -ne 0 -or (($out -join ' ') -notmatch 'PNG')){ throw 'PNG detection test failed' }
& $exe --version
if($LASTEXITCODE -ne 0){ throw 'Version test failed' }
Remove-Item $tmp -Force
Write-Output 'v1 smoke tests passed.'




