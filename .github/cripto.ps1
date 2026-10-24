<#
  Pacotes criptografados da nuvem (o mesmo arquivo roda no PC e no GitHub Actions).

  O repositório é público, então código, .env e histórico vão para o GitHub dentro de pacotes
  (release "nuvem") compactados e criptografados com a CHAVE_NUVEM: AES-256-CBC + HMAC-SHA256.
  Sem a chave, quem baixa o pacote só vê bytes aleatórios.

    . .\cripto.ps1                                     carrega as funções (uso pelo nuvem.ps1)
    .\cripto.ps1 abrir  pacote.enc  pasta-destino     descompacta por cima da pasta
    .\cripto.ps1 fechar pasta-origem pacote.enc        compacta e criptografa a pasta inteira

  A chave (32 bytes em base64) vem do parâmetro -Chave ou da variável de ambiente CHAVE_NUVEM.
#>
param(
  [string]$Acao = '',
  [string]$De = '',
  [string]$Para = '',
  [string]$Chave = $env:CHAVE_NUVEM
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

function Get-ChavesNuvem([string]$chave) {
  if (-not $chave) { throw 'CHAVE_NUVEM não definida.' }
  $bruta = [Convert]::FromBase64String($chave.Trim())
  if ($bruta.Length -ne 32) { throw 'CHAVE_NUVEM inválida (precisa ter 32 bytes em base64).' }
  $sha = [Security.Cryptography.SHA512]::Create()
  $k = $sha.ComputeHash($bruta); $sha.Dispose()
  $kAes = New-Object byte[] 32; $kMac = New-Object byte[] 32
  [Array]::Copy($k, 0, $kAes, 0, 32); [Array]::Copy($k, 32, $kMac, 0, 32)
  @{ aes = $kAes; mac = $kMac }
}

function Lock-Pasta([string]$origem, [string]$destino, [string]$chave) {
  $ch = Get-ChavesNuvem $chave
  $zip = [IO.Path]::GetTempFileName()
  Remove-Item $zip
  [IO.Compression.ZipFile]::CreateFromDirectory((Resolve-Path $origem).Path, $zip, [IO.Compression.CompressionLevel]::Optimal, $false)
  $plano = [IO.File]::ReadAllBytes($zip); Remove-Item $zip
  $aes = [Security.Cryptography.Aes]::Create()
  $aes.Mode = [Security.Cryptography.CipherMode]::CBC; $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
  $aes.Key = $ch.aes; $aes.GenerateIV(); $iv = $aes.IV
  $enc = $aes.CreateEncryptor(); $cifra = $enc.TransformFinalBlock($plano, 0, $plano.Length); $enc.Dispose(); $aes.Dispose()
  $hmac = [Security.Cryptography.HMACSHA256]::new($ch.mac)
  $assinado = New-Object byte[] (16 + $cifra.Length)
  [Array]::Copy($iv, 0, $assinado, 0, 16); [Array]::Copy($cifra, 0, $assinado, 16, $cifra.Length)
  $mac = $hmac.ComputeHash($assinado); $hmac.Dispose()
  # formato: "NV1" + iv(16) + hmac(32) + cifra
  $saida = New-Object IO.MemoryStream
  $saida.Write([byte[]](0x4E, 0x56, 0x31), 0, 3)
  $saida.Write($iv, 0, 16); $saida.Write($mac, 0, 32); $saida.Write($cifra, 0, $cifra.Length)
  $pastaDestino = Split-Path -Parent $destino
  if ($pastaDestino) { [void](New-Item -ItemType Directory -Force $pastaDestino) }
  [IO.File]::WriteAllBytes($destino, $saida.ToArray())
}

function Unlock-Pasta([string]$pacote, [string]$destino, [string]$chave) {
  $ch = Get-ChavesNuvem $chave
  $b = [IO.File]::ReadAllBytes((Resolve-Path $pacote).Path)
  if ($b.Length -lt 51 -or $b[0] -ne 0x4E -or $b[1] -ne 0x56 -or $b[2] -ne 0x31) { throw "$pacote não é um pacote da nuvem." }
  $iv = New-Object byte[] 16; $mac = New-Object byte[] 32
  [Array]::Copy($b, 3, $iv, 0, 16); [Array]::Copy($b, 19, $mac, 0, 32)
  $cifra = New-Object byte[] ($b.Length - 51); [Array]::Copy($b, 51, $cifra, 0, $cifra.Length)
  $assinado = New-Object byte[] (16 + $cifra.Length)
  [Array]::Copy($iv, 0, $assinado, 0, 16); [Array]::Copy($cifra, 0, $assinado, 16, $cifra.Length)
  $hmac = [Security.Cryptography.HMACSHA256]::new($ch.mac)
  $conf = $hmac.ComputeHash($assinado); $hmac.Dispose()
  if ([Convert]::ToBase64String($conf) -ne [Convert]::ToBase64String($mac)) { throw "$pacote não abre com esta CHAVE_NUVEM (chave errada ou arquivo corrompido)." }
  $aes = [Security.Cryptography.Aes]::Create()
  $aes.Mode = [Security.Cryptography.CipherMode]::CBC; $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
  $aes.Key = $ch.aes; $aes.IV = $iv
  $dec = $aes.CreateDecryptor(); $plano = $dec.TransformFinalBlock($cifra, 0, $cifra.Length); $dec.Dispose(); $aes.Dispose()
  [void](New-Item -ItemType Directory -Force $destino)
  $raiz = [IO.Path]::GetFullPath((Resolve-Path $destino).Path).TrimEnd('\') + '\'
  $zip = New-Object IO.Compression.ZipArchive((New-Object IO.MemoryStream(, $plano)), [IO.Compression.ZipArchiveMode]::Read)
  try {
    foreach ($e in $zip.Entries) {
      $alvo = [IO.Path]::GetFullPath((Join-Path $raiz ($e.FullName -replace '/', '\')))
      if (-not $alvo.StartsWith($raiz, [StringComparison]::OrdinalIgnoreCase)) { throw "Caminho inválido no pacote: $($e.FullName)" }
      if ($e.FullName.EndsWith('/') -or $e.FullName.EndsWith('\')) { [void](New-Item -ItemType Directory -Force $alvo); continue }
      [void](New-Item -ItemType Directory -Force (Split-Path -Parent $alvo))
      [IO.Compression.ZipFileExtensions]::ExtractToFile($e, $alvo, $true)
    }
  } finally { $zip.Dispose() }
}

switch ($Acao) {
  'abrir'  { Unlock-Pasta $De $Para $Chave; Write-Host "Aberto: $De -> $Para" }
  'fechar' { Lock-Pasta $De $Para $Chave; Write-Host "Fechado: $De -> $Para ($([math]::Round((Get-Item $Para).Length / 1KB)) KB)" }
  ''       { }
  default  { throw "Ação desconhecida: $Acao (use abrir ou fechar)" }
}
