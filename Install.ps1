$GitHubRawUriPrefix = 'https://raw.githubusercontent.com/PixelFrame/LuaShark/master/'
$Scripts = @('ndiswan.lua', 'mscluster.lua', 'dfsc.lua')
$OrderPrefix = 97

if (!(Test-Path "$env:APPDATA/Wireshark/plugins")) {
    mkdir "$env:APPDATA/Wireshark/plugins"
}

foreach ($Script in $Scripts) {
    $FileName = ([char]$OrderPrefix) + "-" + $Script
    $OrderPrefix++
    Invoke-WebRequest -Uri ($GitHubRawUriPrefix + $Script) -UseBasicParsing -OutFile "$env:APPDATA/Wireshark/plugins/$FileName"
}