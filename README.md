PSBouncyCastle
==============

**PSBouncyCastle** is a PowerShell module that allows you to use the
crypto functionality from the [Legion of the BouncyCastle](http://www.bouncycastle.org/)
.NET libraries.

Currently it covers the X509 certificate functionality, in particular
allowing you to replace `makecert.exe` (from the Windows SDK) with
native PowerShell cmdlets.

It accompanies my [series of blog posts](http://blog.differentpla.net/tag/bouncy-castle) about using Bouncy Castle [from C#](http://blog.differentpla.net/b/2013/21/18/how-do-i-create-a-self-signed-certificate-using-bouncy-castle-) and [from PowerShell](http://blog.differentpla.net/b/2013/31/17/how-do-i-use-bouncy-castle-from-powershell-).

Installation
--

	Set-Location (Join-Path (Split-Path $PROFILE) 'Modules')
	git clone https://github.com/rlipscombe/PSBouncyCastle.git
	Import-Module PSBouncyCastle

*Note:* I'll get this listed on [PsGet](http://psget.net/) at some point.
