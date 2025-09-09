<#
# ==============================================================================================
# THIS SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
# FITNESS FOR A PARTICULAR PURPOSE.
#
# This sample is not supported under any Microsoft standard support program or service. 
# The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
# implied warranties including, without limitation, any implied warranties of merchantability
# or of fitness for a particular purpose. The entire risk arising out of the use or performance
# of the sample and documentation remains with you. In no event shall Microsoft, its authors,
# or anyone else involved in the creation, production, or delivery of the script be liable for 
# any damages whatsoever (including, without limitation, damages for loss of business profits, 
# business interruption, loss of business information, or other pecuniary loss) arising out of 
# the use of or inability to use the sample or documentation, even if Microsoft has been advised 
# of the possibility of such damages.
# ==============================================================================================
#
## ALL LINES STARTING WITH # are comments only and do not apply during script processing.
# THIS SCRIPT IS FULLY AUTOMATED
#
#################
# 
# by andreas.luy@microsoft.con & dagmar.heidecker@microsoft.com
# 
#
.Synopsis
    This script extracts the private key from earlier created protected P12 files and
    writes it into an unproteced PEM file to recover Azure Cloud HSM Security Domain

.DESCRIPTION
    The script recovers the required key material, stores it as unprotected PEM file 
    to recover an Azure Managed HSM security domain

.EXAMPLE
    .\SecDomainRecoveryKeyExtraction.ps1 [-FilePath <p12/pfx file>]

.NOTES
    Version Tracking
    Version 1.0
        - First internal release
        - 04.09.2025

#>
Param (
    [Parameter(Mandatory=$false)]
    [String]$FilePath
)

# loading .net classes needed
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

if ($psISE) {
    $ScriptPath = Split-Path -Parent -Path $psISE.CurrentFile.FullPath
} else {
    $ScriptPath = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
}

$Now = $(Get-Date -f yyyyMMdd-HHmmss)
$Logfile = "$($ScriptPath)\AzureManagedHSM-RecoveryKeyExtraction-$($subject)-$($Now).log"

function Write-Message
{
    param(
        [Parameter(mandatory=$true)][string]$Message,
        [Parameter(mandatory=$false)]
        [ValidateSet("Success", "Failure", "Info")]
        [string]$Type = "Info",
        [switch]$LogFileOnly
    )

    switch ($type) {
        "Success" {$Color = "Green"}
        "Failure" {$Color = "Red"}
        "Info" {$Color = "Yellow"}
    }
    
    if (!$LogFileOnly) {
        Write-Host $Message -ForegroundColor $Color
    }
    Add-Content $LogFile -Value $Message
}

function Decrypt-SecString
{
    param(
        [Parameter(mandatory=$true)]$SecStr
    )
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecStr)
    $Pwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    return $Pwd
}

function Select-Pkcsfile
{
    $ConfigFileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
        InitialDirectory = $BaseDirectory 
        Filter = 'PKCS#12 (*.pfx,*.p12)|*.pfx;*.p12'
        Title = "select Quorum key file ..."
    }
    [void] $ConfigFileBrowser.ShowDialog()
    return ($ConfigFileBrowser.filename)
}

function Check-PwdValid 
{
      param(
            [Parameter(mandatory=$true)]$Pwd,
            [Parameter(mandatory=$true)]$P12File
      )

      $ret = $true
      try {
            Get-PfxData -FilePath $P12File -Password $Pwd -ErrorAction Stop | Out-Null
      } catch {
            $ret = $false
      }
      return $ret      
}

function Check-PoSPrereqs {
      $ret = $true
      
      #PowerShell 7.x or higher required
      if (($PSVersionTable.PSVersion.Major) -lt 7) {
            $ret = $false
      }
      return $ret
}

##
## main program starts here
##
#region Prepare console window
if ($host.name -eq 'ConsoleHost') {
    try {
        $pshost = get-host
        $pswindow = $pshost.ui.rawui
        $newsize = $pswindow.buffersize
        $newsize.height = 60
        $newsize.width = 60
        $pswindow.buffersize = $newsize
        $newsize = $pswindow.windowsize
        $newsize.height = 60
        $newsize.width = 140
        $pswindow.windowsize = $newsize
    } catch {
        #issues with resizing...
        #anyway no need to do something
    }
    Clear-Host

    $pswindow.windowtitle = "Azure Managed HSM Secure Domain Recovery KeyExtraction Ceremony"
    $pswindow.foregroundcolor = "White"
    $pswindow.backgroundcolor = "Black"
}

#endregion

#we assume all goes well
$failed = $false

if (!(Check-PoSPrereqs)) {
      $failed = $true
      Write-Message -Message "########################################################" 
      Write-Message -Message "  PowerShell 7.x or higher is required for running this script!" -Type Failure
      Write-Message -Message "########################################################"
      Exit
}

#works for PoS 5+
Write-Message -Message "########################################################"
Write-Message -Message "Starting Key Recovery Key Extraction Ceremony at: $(Get-Date)"
Write-Message -Message " "


if ($FilePath) {
      #does filespath exist?
      if (Test-Path $FilePath) {
            #if so, convert to filesystem object
            $FilePath = Get-Item $FilePath
      } else {
            Write-Message -Message " $($FilePath) not found!" -Type Failure
            Write-Message -Message " opening file selector ..."
            $FilePath = $null
      }
}
If (!$FilePath) {
    $FilePath = Select-Pkcsfile
    if(!$FilePath){
        Write-Message -Message " No PKCS#12 key file selected!`r`nAborting ..." -Type Failure
        $failed = $true
        Exit
    }
}

Write-Message -Message "$($FilePath.FullName) selected!" -Type Success
$KeyFileName = "$($FilePath.DirectoryName)\$($FilePath.BaseName).pem"

#get password for p12 file
$exitLoop = $false
do {
      $passwd = Read-Host -Prompt "Enter password for $($FilePath)" -AsSecureString
      if (!(Check-PwdValid -P12File $FilePath -Pwd $passwd)) {
            Write-Message -Message " The passwords do not work for $($FilePath) - please try again ..." -Type Failure
      } else {
            $EncPwd = Decrypt-SecString -SecStr $passwd
            $exitLoop = $true
      }
} while (!$exitLoop)

Write-Message -Message " Accessing PKCS12 file $($FilePath) ..."
try {
      #Password must be a plain string, not a securestring (needs to be converted as we treat any pwd as sec string)
      $cert=New-Object System.Security.Cryptography.X509Certificates.X509Certificate2( 
            $FilePath, 
            $EncPwd, 
            [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
      Write-Message -Message " $($FilePath) successfully opened!" -Type Success
} catch {
      Write-Message -Message " Opening $($FilePath) failed with error: `r`n$($_.Exception.Message)`r`n`r`nAborting ..." -Type Failure
      $failed = $true
}

if (!$failed) {
      Write-Message -Message " Accessing private key ..."
      try {
            #Read the private key into an RSA CNG object (need to test if that works for ECC as well)
            $RSACng = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            Write-Message -Message " Success!" -Type Success
      } catch {
            Write-Message -Message " Private key access failed with error: `r`n$($_.Exception.Message)`r`n`r`nAborting ..." -Type Failure
            $failed = $true
      }

      if (!$failed) {
            Write-Message -Message " Extracting private key blob ..."
            try {
                  #Get private key as bytes array (blob)
                  $KeyBytes = $rsaCng.ExportRSAPrivateKey()
                  #$KeyBytes = $RSACng.Key.Export([Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob)
                  Write-Message -Message " Success!" -Type Success
            } catch {
                  Write-Message -Message " Extracting private key blob failed with error: `r`n$($_.Exception.Message)`r`n`r`nAborting ..." -Type Failure
                  $failed = $true
            }
      }

      if (!$failed) {
            Write-Message -Message " Converting private key to base64 PEM ..."
            try {
                  #convert byte array to base64 string
                  $KeyBase64 = [Convert]::ToBase64String($KeyBytes, [Base64FormattingOptions]::InsertLineBreaks)
                  Write-Message -Message " Success!" -Type Success
            } catch {
                  Write-Message -Message " Coverting private key failed with error: `r`n$($_.Exception.Message)`r`n`r`nAborting ..." -Type Failure
                  $failed = $true
            }
      }

      if (!$failed) {
            Write-Message -Message " Writing private key to PEM key file: $($KeyFileName) ..."

            try {
                  #include base64 string into mandatory envelop
                  $KeyPem = @"
-----BEGIN PRIVATE KEY-----
$KeyBase64
-----END PRIVATE KEY-----
"@
                  $KeyPem | Out-File -Encoding utf8 $KeyFileName -ErrorAction Stop
                  Write-Message -Message " Success!" -Type Success
            } catch {
                  Write-Message -Message " Could not write private key to PEM file with error: `r`n$($_.Exception.Message)`r`n`r`nAborting ..." -Type Failure
                  $failed = $true
            }
      }
}
$cert.Dispose()

Write-Message -Message "#################################################################"
Write-Message -Message " "
if ($failed) {
    Write-Message -Message " Azure Managed HSM Recovery Key Extraction Ceremony failed !" -Type Failure
    Write-Message -Message " Review errors messages and correct any issue before continuing !" -Type Failure
} else {
    Write-Message -Message " Azure Managed HSM Recovery Key Extraction Ceremony completed successfully !" -Type Success
      Write-Message -Message " Please ensure that you are deleting the PEM keys after usage !" -Type Success
      Write-Message -Message " NEVER GIVE ANYONE ELSE ACCESS TO YOUR PEM KEY FILE." -Type Success
}
Write-Message -Message " "
Write-Message -Message "#################################################################"

