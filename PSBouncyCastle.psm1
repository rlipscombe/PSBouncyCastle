# PowerShell module for using the cryptography libraries from the Legion of the Bouncy Castle.
# Copyright (c) 2013 Roger Lipscombe. MIT license.

# Assumes that you've got the NuGet package for BouncyCastle.Crypto installed in 'packages'
$thisFolder = Split-Path $script:MyInvocation.MyCommand.Path
$assemblyPath = switch -wildcard ($PSVersionTable.CLRVersion) {
    "4.0.*" { 'packages\BouncyCastle.1.7.0\lib\Net40-Client\BouncyCastle.Crypto.dll' }
    "2.0.*" { 'packages\BouncyCastle.1.7.0\lib\Net20\BouncyCastle.Crypto.dll' }
}

Add-Type -Path (Join-Path $thisFolder $assemblyPath)

<#
.SYNOPSIS

Create a new (random) serial number, suitable for use with an X.509 certificate.
#>
function New-SerialNumber
{
param(
    # Allows you to specify the random number generator to be used. If not specified, a new one is created.
    [Parameter(Mandatory = $false)]
    [Org.BouncyCastle.Security.SecureRandom] $Random = (New-SecureRandom)
)

    $serialNumber =
        [Org.BouncyCastle.Utilities.BigIntegers]::CreateRandomInRange(
            [Org.BouncyCastle.Math.BigInteger]::One,
            [Org.BouncyCastle.Math.BigInteger]::ValueOf([Int64]::MaxValue),
            $random)

    return $serialNumber
}

function New-CertificateGenerator
{
    $certificateGenerator = New-Object Org.BouncyCastle.X509.X509V3CertificateGenerator
    return $certificateGenerator
}

function New-SecureRandom
{
    $randomGenerator = New-Object Org.BouncyCastle.Crypto.Prng.CryptoApiRandomGenerator
    $random = New-Object Org.BouncyCastle.Security.SecureRandom($randomGenerator)

    return $random
}

<#
.SYNOPSIS

Generate an RSA key pair suitable for use with an X.509 certificate.
#>
function New-KeyPair
{
param(
    # Allows you to specify the random number generator to be used. If not specified, a new one is created.
    [Parameter(Mandatory = $false)]
    [Org.BouncyCastle.Security.SecureRandom] $Random = (New-SecureRandom),

    # The strength (in bits) of the RSA key generated. Defaults to 2048 bits.
    [Parameter(Mandatory = $false)]
    [int] $Strength = 2048
)

    $keyGenerationParameters = New-Object Org.BouncyCastle.Crypto.KeyGenerationParameters($Random, $Strength)

    $keyPairGenerator = New-Object Org.BouncyCastle.Crypto.Generators.RsaKeyPairGenerator
    $keyPairGenerator.Init($keyGenerationParameters)
    $keyPair = $keyPairGenerator.GenerateKeyPair()

    return $keyPair
}

function ConvertFrom-BouncyCastleCertificate
{
param(
    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.X509.X509Certificate] $certificate,

    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair] $subjectKeyPair,

    [Parameter(Mandatory = $true)]
    [string] $friendlyName
)

    $store = New-Object Org.BouncyCastle.Pkcs.Pkcs12Store

    $certificateEntry = New-Object Org.BouncyCastle.Pkcs.X509CertificateEntry($certificate)
    $store.SetCertificateEntry($friendlyName, $certificateEntry)

    $keyEntry = New-Object Org.BouncyCastle.Pkcs.AsymmetricKeyEntry($subjectKeyPair.Private)
    $store.SetKeyEntry($friendlyName, $keyEntry, @($certificateEntry))

    # The password is re-used immediately, so it doesn't matter what it is.
    $password = 'password'
    $stream = New-Object System.IO.MemoryStream
    $store.Save($stream, $password, $random)

    $keyStorageFlags = 'PersistKeySet, Exportable'
    $result =
        New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $stream.ToArray(), $password, $keyStorageFlags)

    $stream.Dispose()

    return $result
}

function ConvertTo-BouncyCastleKeyPair
{
param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.AsymmetricAlgorithm] $PrivateKey
)

    return [Org.BouncyCastle.Security.DotNetUtilities]::GetKeyPair($PrivateKey)
}

function New-AuthorityKeyIdentifier
{
param(
    [Parameter(Mandatory = $true)]
    [string] $name,

    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters] $publicKey,

    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Math.BigInteger] $serialNumber
)

    $publicKeyInfo =
        [Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory]::CreateSubjectPublicKeyInfo($publicKey)

    $generalName = New-Object Org.BouncyCastle.Asn1.X509.GeneralName($name)
    $generalNames = New-Object Org.BouncyCastle.Asn1.X509.GeneralNames($generalName)

    $authorityKeyIdentifier =
        New-Object Org.BouncyCastle.Asn1.X509.AuthorityKeyIdentifier(
            $publicKeyInfo, $generalNames, $serialNumber)

    return $authorityKeyIdentifier
}

function Add-AuthorityKeyIdentifier
{
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [Org.BouncyCastle.X509.X509V3CertificateGenerator] $certificateGenerator,

    [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $false)]
    [Org.BouncyCastle.Asn1.X509.AuthorityKeyIdentifier] $authorityKeyIdentifier
)

    $certificateGenerator.AddExtension(
        [Org.BouncyCastle.Asn1.X509.X509Extensions]::AuthorityKeyIdentifier.Id,
        $false,
        $authorityKeyIdentifier)

    return $certificateGenerator
}

function New-SubjectKeyIdentifier
{
param(
    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Crypto.Parameters.RsaKeyParameters] $publicKey
)

    $publicKeyInfo =
        [Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory]::CreateSubjectPublicKeyInfo($publicKey)

    $subjectKeyIdentifier =
        New-Object Org.BouncyCastle.Asn1.X509.SubjectKeyIdentifier($publicKeyInfo)

    return $subjectKeyIdentifier
}

function Add-SubjectKeyIdentifier
{
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [Org.BouncyCastle.X509.X509V3CertificateGenerator] $certificateGenerator,

    [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $false)]
    [Org.BouncyCastle.Asn1.X509.SubjectKeyIdentifier] $subjectKeyIdentifier
)

    $certificateGenerator.AddExtension(
        [Org.BouncyCastle.Asn1.X509.X509Extensions]::SubjectKeyIdentifier.Id,
        $false,
        $subjectKeyIdentifier)

    return $certificateGenerator
}

function Add-BasicConstraints
{
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [Org.BouncyCastle.X509.X509V3CertificateGenerator] $certificateGenerator,

    [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $false)]
    [bool] $isCertificateAuthority
)

    $basicConstraints =
        New-Object Org.BouncyCastle.Asn1.X509.BasicConstraints($isCertificateAuthority)
    $certificateGenerator.AddExtension(
        [Org.BouncyCastle.Asn1.X509.X509Extensions]::BasicConstraints.Id,
        $true,
        $basicConstraints)

    return $certificateGenerator
}

function Add-SubjectAlternativeName
{
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [Org.BouncyCastle.X509.X509V3CertificateGenerator] $CertificateGenerator,

    [Parameter(Mandatory = $true)]
    [string[]] $DnsName
)

    $names = $DnsName |
        foreach {
            New-Object Org.BouncyCastle.Asn1.X509.GeneralName(
                [Org.BouncyCastle.Asn1.X509.GeneralName]::DnsName, $_)
            }

    $extension = New-Object Org.BouncyCastle.Asn1.DerSequence($names)

    $CertificateGenerator.AddExtension(
        [Org.BouncyCastle.Asn1.X509.X509Extensions]::SubjectAlternativeName.Id,
        $false,
        $extension)

    return $CertificateGenerator
}

function Add-KeyUsage
{
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [Org.BouncyCastle.X509.X509V3CertificateGenerator] $certificateGenerator,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
    [switch] $DigitalSignature,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
    [switch] $NonRepudiation,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
    [switch] $KeyEncipherment,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
    [switch] $DataEncipherment,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
    [switch] $KeyAgreement,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
    [switch] $KeyCertSign,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
    [switch] $CrlSign,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
    [switch] $EncipherOnly,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false)]
    [switch] $DecipherOnly
)

    $usages = 0
    if ($DigitalSignature) { $usages = $usages -bor [Org.BouncyCastle.Asn1.X509.KeyUsage]::DigitalSignature }
    if ($NonRepudiation) {  $usages = $usages -bor [Org.BouncyCastle.Asn1.X509.KeyUsage]::NonRepudiation }
    if ($KeyEncipherment) { $usages = $usages -bor [Org.BouncyCastle.Asn1.X509.KeyUsage]::KeyEncipherment }
    if ($DataEncipherment) { $usages = $usages -bor [Org.BouncyCastle.Asn1.X509.KeyUsage]::DataEncipherment }
    if ($KeyAgreement) { $usages = $usages -bor [Org.BouncyCastle.Asn1.X509.KeyUsage]::KeyAgreement }
    if ($KeyCertSign) { $usages = $usages -bor [Org.BouncyCastle.Asn1.X509.KeyUsage]::KeyCertSign }
    if ($CrlSign) { $usages = $usages -bor [Org.BouncyCastle.Asn1.X509.KeyUsage]::CrlSign }
    if ($EncipherOnly) { $usages = $usages -bor [Org.BouncyCastle.Asn1.X509.KeyUsage]::EncipherOnly }
    if ($DecipherOnly) { $usages = $usages -bor [Org.BouncyCastle.Asn1.X509.KeyUsage]::DecipherOnly }

    $keyUsage = New-Object Org.BouncyCastle.Asn1.X509.KeyUsage -ArgumentList $usages
    $certificateGenerator.AddExtension(
        [Org.BouncyCastle.Asn1.X509.X509Extensions]::KeyUsage.Id,
        $true,
        $keyUsage)

    return $certificateGenerator
}

function Add-ExtendedKeyUsage
{
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [Org.BouncyCastle.X509.X509V3CertificateGenerator] $certificateGenerator,

    [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'Oid')]
    [string[]] $Oid = $null,

    [Parameter(Mandatory = $true, ValueFromPipeline = $false, ParameterSetName = 'AnyPurpose')]
    [switch] $AnyPurpose,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Named')]
    [switch] $ServerAuthentication,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Named')]
    [switch] $ClientAuthentication,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Named')]
    [switch] $CodeSigning,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Named')]
    [switch] $EmailProtection,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Named')]
    [switch] $IpsecEndSystem,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Named')]
    [switch] $IpsecTunnel,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Named')]
    [switch] $IpsecUser,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Named')]
    [switch] $TimeStamping,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Named')]
    [switch] $OcspSigning,

    [Parameter(Mandatory = $false, ValueFromPipeline = $false, ParameterSetName = 'Named')]
    [switch] $SmartCardLogon
)

    $usages = switch ($PSCmdlet.ParameterSetName) {
        "Oid" {
            [Org.BouncyCastle.Asn1.Asn1Object[]] $usages = @()
            $Oid | % { $usages += New-Object Org.BouncyCastle.Asn1.DerObjectIdentifier($_) }
            $usages
        }

        "AnyPurpose" {
            @( [Org.BouncyCastle.Asn1.X509.KeyPurposeID]::AnyExtendedKeyUsage )
        }

        "Named" {
            $usages = @()
            if ($ServerAuthentication) { $usages += [Org.BouncyCastle.Asn1.X509.KeyPurposeID]::IdKPServerAuth }
            if ($ClientAuthentication) { $usages += [Org.BouncyCastle.Asn1.X509.KeyPurposeID]::IdKPClientAuth }
            if ($CodeSigning) { $usages += [Org.BouncyCastle.Asn1.X509.KeyPurposeID]::IdKPCodeSigning }
            if ($EmailProtection) { $usages += [Org.BouncyCastle.Asn1.X509.KeyPurposeID]::IdKPEmailProtection }
            if ($IpsecEndSystem) { $usages += [Org.BouncyCastle.Asn1.X509.KeyPurposeID]::IdKPIpsecEndSystem }
            if ($IpsecTunnel) { $usages += [Org.BouncyCastle.Asn1.X509.KeyPurposeID]::IdKPIpsecTunnel }
            if ($IpsecUser) { $usages += [Org.BouncyCastle.Asn1.X509.KeyPurposeID]::IdKPIpsecUser }
            if ($TimeStamping) { $usages += [Org.BouncyCastle.Asn1.X509.KeyPurposeID]::IdKPTimeStamping }
            if ($OcspSigning) { $usages += [Org.BouncyCastle.Asn1.X509.KeyPurposeID]::IdKPOcspSigning }
            if ($SmartCardLogon) { $usages += [Org.BouncyCastle.Asn1.X509.KeyPurposeID]::IdKPSmartCardLogon }
            $usages
        }
    }

    $extendedKeyUsage = New-Object Org.BouncyCastle.Asn1.X509.ExtendedKeyUsage(,$usages)
    $certificateGenerator.AddExtension(
        [Org.BouncyCastle.Asn1.X509.X509Extensions]::ExtendedKeyUsage.Id,
        $false,
        $extendedKeyUsage)

    return $certificateGenerator
}

function New-X509Name
{
param(
    [Parameter(Mandatory = $true)]
    [string] $Name
)

    New-Object Org.BouncyCastle.Asn1.X509.X509Name($Name)
}

function New-Certificate
{
param(
    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Security.SecureRandom] $Random,

    [Parameter(Mandatory = $true)]
    [string] $IssuerName,

    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair] $IssuerKeyPair,

    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Math.BigInteger] $IssuerSerialNumber,

    [Parameter(Mandatory = $true)]
    [string] $SubjectName,

    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair] $SubjectKeyPair,

    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Math.BigInteger] $SubjectSerialNumber,

    [Parameter(Mandatory = $true)]
    [Alias("IsCertificateAuthority")]
    [bool] $IsCA,

    [Parameter(Mandatory = $false)]
    [string[]] $Eku
)

    $certificateGenerator = New-CertificateGenerator

    $certificateGenerator.SetSerialNumber($SubjectSerialNumber)

    $signatureAlgorithm = "SHA256WithRSA"
    $certificateGenerator.SetSignatureAlgorithm($signatureAlgorithm)

    $issuerDN = New-X509Name($IssuerName)
    $certificateGenerator.SetIssuerDN($issuerDN)

    $subjectDN = New-X509Name($SubjectName)
    $certificateGenerator.SetSubjectDN($subjectDN)

    $notBefore = [DateTime]::UtcNow.Date
    $notAfter = $notBefore.AddYears(2)

    $certificateGenerator.SetNotBefore($notBefore)
    $certificateGenerator.SetNotAfter($notAfter)

    $certificateGenerator.SetPublicKey($SubjectKeyPair.Public)

    $certificateGenerator |
        Add-SubjectKeyIdentifier (New-SubjectKeyIdentifier $SubjectKeyPair.Public) |
        Add-AuthorityKeyIdentifier (New-AuthorityKeyIdentifier $IssuerName $IssuerKeyPair.Public $IssuerSerialNumber) |
        Add-BasicConstraints -IsCertificateAuthority $IsCA |
        Out-Null

    if ($Eku) {
        $certificateGenerator |
            Add-ExtendedKeyUsage -Oid $Eku |
            Out-Null
    }

    $certificate = $certificateGenerator.Generate($IssuerKeyPair.Private, $Random)

    return (ConvertFrom-BouncyCastleCertificate $certificate $SubjectKeyPair $SubjectName)
}

function New-SelfSignedCertificate
{
param(
    [Parameter(Mandatory = $true)]
    [string] $Name,

    [Parameter(Mandatory = $false)]
    [string[]] $Eku = $null
)

    $random = New-SecureRandom
    $serialNumber = New-SerialNumber
    $keyPair = New-KeyPair

    New-Certificate -Random $random `
                    -IssuerName $Name -IssuerKeyPair $keyPair -IssuerSerialNumber $serialNumber `
                    -SubjectName $Name -SubjectKeyPair $keyPair -SubjectSerialNumber $serialNumber `
                    -IsCertificateAuthority $false `
                    -Eku $Eku
}

function New-CertificateAuthorityCertificate
{
param(
    [Parameter(Mandatory = $true)]
    [string] $Name,

    [Parameter(Mandatory = $false)]
    [string[]] $Eku = $null
)

    $random = New-SecureRandom
    $serialNumber = New-SerialNumber
    $keyPair = New-KeyPair

    New-Certificate -Random $random `
                    -IssuerName $Name -IssuerKeyPair $keyPair -IssuerSerialNumber $serialNumber `
                    -SubjectName $Name -SubjectKeyPair $keyPair -SubjectSerialNumber $serialNumber `
                    -IsCertificateAuthority $true `
                    -Eku $Eku
}

function New-IssuedCertificate
{
param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $IssuerCertificate,

    [Parameter(Mandatory = $true)]
    [string] $Name,

    [Parameter(Mandatory = $false)]
    [string[]] $Eku = $null
)

    $issuerName = $IssuerCertificate.Subject
    $issuerKeyPair = ConvertTo-BouncyCastleKeyPair $IssuerCertificate.PrivateKey
    $issuerSerialNumber = New-Object Org.BouncyCastle.Math.BigInteger(,$IssuerCertificate.GetSerialNumber())

    $random = New-SecureRandom
    $subjectSerialNumber = New-SerialNumber
    $subjectKeyPair = New-KeyPair

    New-Certificate -Random $random `
                    -IssuerName $issuerName -IssuerKeyPair $issuerKeyPair -IssuerSerialNumber $issuerSerialNumber `
                    -SubjectName $Name -SubjectKeyPair $subjectKeyPair -SubjectSerialNumber $subjectSerialNumber `
                    -IsCertificateAuthority $false `
                    -Eku $Eku
}

function New-CertificateRequest
{
param(
    [Parameter(Mandatory = $true)]
    [string] $Name
)

    $signatureAlgorithm = 'SHA256WithRSA'
    $subjectDN = New-X509Name $Name
    $keyPair = New-KeyPair
    $attributes = $null

    New-Object Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(
        $signatureAlgorithm, $subjectDN, $keyPair.Public, $attributes, $keyPair.Private)
}

# Save a certificate request as a DER file.
# TODO: Rename this to Export-CertificateRequest
function Save-DerEncoded
{
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [Org.BouncyCastle.Asn1.Pkcs.CertificationRequest] $CertificationRequest,

    [Parameter(Mandatory = $true)]
    [string] $OutputFile
)

    $bytes = $CertificationRequest.GetDerEncoded()
    $path = QualifyPath $OutputFile
    [System.IO.File]::WriteAllBytes($path, $bytes)
}

function QualifyPath($Path)
{
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

# Split a string into lines of a particular length. Used for .PEM export.
function SplitString([string] $String, [int] $Length)
{
    $stringLength = $String.Length
    for ($i = 0; $i -lt $stringLength; $i += $Length)
    {
        if (($i + $Length) -le $stringLength) {
            Write-Output $String.Substring($i, $Length)
        } else {
            Write-Output $String.Substring($i)
        }
    }
}

function Test-CertificateAuthority
{
param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
)

    $Extension = $Certificate.Extensions | where { $_.Oid.Value -eq '2.5.29.19' }
    $Extension.CertificateAuthority
}

function Export-Certificate
{
param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,

    [Parameter(Mandatory = $true)]
    [string] $OutputFile,

    [Parameter(Mandatory = $false)]
    [ValidateSet('PEM', 'DER')]
    [string] $OutputFormat = 'DER',

    [ValidateSet("Cert","Pfx")]
    [string] $X509ContentType = "Cert",

    [Parameter(Mandatory = $false)]
    [ValidateNotNull()]
    [securestring] $Password
)

    $outputPath = QualifyPath $OutputFile

    if ($X509ContentType -eq 'PFX' -and $Password -ne $null) {
        $bytes = $Certificate.Export($X509ContentType, $Password)
    } else {
        $bytes = $Certificate.Export($X509ContentType)
    }

    switch ($OutputFormat)
    {
        'DER' { [System.IO.File]::WriteAllBytes($outputPath, $bytes) }
        'PEM' {
            $prefix = "-----BEGIN CERTIFICATE-----`r`n"
            $suffix = "-----END CERTIFICATE-----`r`n"

            if (Test-CertificateAuthority $Certificate) {
                $prefix = "-----BEGIN CA CERTIFICATE-----`r`n"
                $suffix = "-----END CA CERTIFICATE-----`r`n"
            }

            $encoded = [Convert]::ToBase64String($bytes)
            $lines = SplitString -String $encoded -Length 65
            $content = $prefix
            $lines | % { $content += $_ + "`r`n" }
            $content += $suffix
            [System.IO.File]::WriteAllText($outputPath, $content)
        }
    }
}

function Export-PrivateKey
{
param(
    [Parameter(Mandatory = $true)]
    [System.Security.Cryptography.AsymmetricAlgorithm] $PrivateKey,

    [Parameter(Mandatory = $true)]
    [string] $OutputFile,

    [Parameter(Mandatory = $false)]
    [ValidateSet('PEM', 'DER')]
    [string] $OutputFormat = 'DER'
)

    $outputPath = QualifyPath $OutputFile

    switch ($OutputFormat)
    {
        'DER' { Write-Error "OutputFormat DER not supported yet. Sorry." }
        'PEM' {
            $keyPair = ConvertTo-BouncyCastleKeyPair -Private $PrivateKey
            WritePemObject $keyPair.Private $outputPath
        }
    }
}

function WritePemObject
{
param(
    [Parameter(Mandatory = $true)]
    $Object,

    [Parameter(Mandatory = $true)]
    $OutputPath
)

    $w = New-Object System.IO.StreamWriter $OutputPath
    $pw = New-Object Org.BouncyCastle.OpenSsl.PemWriter $w

    $pw.WriteObject($Object)
    $pw.Writer.Flush()

    $w.Close()
}

Export-ModuleMember New-SerialNumber
Export-ModuleMember New-CertificateGenerator
Export-ModuleMember New-SecureRandom
Export-ModuleMember New-KeyPair
Export-ModuleMember ConvertFrom-BouncyCastleCertificate
Export-ModuleMember ConvertTo-BouncyCastleKeyPair
Export-ModuleMember New-AuthorityKeyIdentifier
Export-ModuleMember Add-AuthorityKeyIdentifier
Export-ModuleMember New-SubjectKeyIdentifier
Export-ModuleMember Add-SubjectKeyIdentifier
Export-ModuleMember Add-BasicConstraints
Export-ModuleMember Add-SubjectAlternativeName
Export-ModuleMember Add-KeyUsage
Export-ModuleMember Add-ExtendedKeyUsage
Export-ModuleMember New-X509Name
Export-ModuleMember New-Certificate
Export-ModuleMember New-SelfSignedCertificate
Export-ModuleMember New-CertificateAuthorityCertificate
Export-ModuleMember New-IssuedCertificate
Export-ModuleMember New-CertificateRequest
Export-ModuleMember Save-DerEncoded
Export-ModuleMember Export-Certificate
Export-ModuleMember Export-PrivateKey
