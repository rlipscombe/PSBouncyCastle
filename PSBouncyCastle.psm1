# PowerShell module for using the cryptography libraries from the Legion of the Bouncy Castle.
# Copyright (c) 2013 Roger Lipscombe. MIT license.

# Assumes that you've got the NuGet package for BouncyCastle.Crypto installed in 'packages'
$thisFolder = Split-Path $script:MyInvocation.MyCommand.Path
$assemblyPath = switch -wildcard ($PSVersionTable.CLRVersion) {
    "4.0.*" { 'packages\BouncyCastle.1.7.0\lib\Net40-Client\BouncyCastle.Crypto.dll' }
    "2.0.*" { 'packages\BouncyCastle.1.7.0\lib\Net20\BouncyCastle.Crypto.dll' }
}

Add-Type -Path (Join-Path $thisFolder $assemblyPath)

function New-SerialNumber(
    [Org.BouncyCastle.Security.SecureRandom] $random)
{
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

function New-KeyPair
{
param(
    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Security.SecureRandom] $random,

    [Parameter(Mandatory = $false)]
    [int] $strength = 2048
)

    $keyGenerationParameters = New-Object Org.BouncyCastle.Crypto.KeyGenerationParameters($random, $strength)

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

function New-Certificate
{
param(
    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Security.SecureRandom] $random,

    [Parameter(Mandatory = $true)]
    [string] $issuerName,

    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair] $issuerKeyPair,

    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Math.BigInteger] $issuerSerialNumber,

    [Parameter(Mandatory = $true)]
    [string] $subjectName,

    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair] $subjectKeyPair,

    [Parameter(Mandatory = $true)]
    [Org.BouncyCastle.Math.BigInteger] $subjectSerialNumber,

    [Parameter(Mandatory = $true)]
    [bool] $isCA
)

    $certificateGenerator = New-CertificateGenerator
   
    $certificateGenerator.SetSerialNumber($subjectSerialNumber)

    $signatureAlgorithm = "SHA256WithRSA"
    $certificateGenerator.SetSignatureAlgorithm($signatureAlgorithm)

    $issuerDN = New-Object Org.BouncyCastle.Asn1.X509.X509Name($issuerName)
    $certificateGenerator.SetIssuerDN($issuerDN)

    $subjectDN = New-Object Org.BouncyCastle.Asn1.X509.X509Name($subjectName)
    $certificateGenerator.SetSubjectDN($subjectDN)

    $notBefore = [DateTime]::UtcNow.Date
	$notAfter = $notBefore.AddYears(2)

	$certificateGenerator.SetNotBefore($notBefore)
	$certificateGenerator.SetNotAfter($notAfter)

	$certificateGenerator.SetPublicKey($subjectKeyPair.Public)

    $certificateGenerator |
        Add-SubjectKeyIdentifier (New-SubjectKeyIdentifier $subjectKeyPair.Public) |
        Add-AuthorityKeyIdentifier (New-AuthorityKeyIdentifier $issuerName $issuerKeyPair.Public $issuerSerialNumber) |
        Add-BasicConstraints -IsCertificateAuthority $isCA |
        Out-Null

    $certificate = $certificateGenerator.Generate($issuerKeyPair.Private, $random)

    return (ConvertFrom-BouncyCastleCertificate $certificate $subjectKeyPair $subjectName)
}
