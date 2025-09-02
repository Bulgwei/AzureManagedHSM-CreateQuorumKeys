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
# by dagmar.heidecker@microsoft.com
# 
#
.Synopsis
    This script creates self signed certificates for storing the Quorum key to administer 
    Azure Cloud HSM Security Domain

.DESCRIPTION
    The script creates the required key material, stores it as PKCS12 enveloped file 
    and creates a Quorum certificate for uploading into the Azure Managed HSM
    The key material can be created in software or in hardware (SmartCard) as long
    as the smar card uses the default "Microsoft Smart Card Key Storage Provider"

.EXAMPLE
    .\CreateQuorumKeys.ps1 -Subject <subject name> [-ValidityTime <5-30> -KeyLength <2048,3084,4096>] [-Enroll2SmartCard]

.NOTES
    Version Tracking
    Version 1.0
        - First internal release
        - 28.08.2025

#>

Param (
    [Parameter(Mandatory=$false)]
    [String]$Subject,
    [Parameter(Mandatory=$false)]
    [String]$FilePath,
    [Parameter(Mandatory=$false)]
    [ValidateRange(5,30)][int]$ValidityTime = 5,
    [Parameter(Mandatory=$false)]
    [ValidateSet(2048,3084,4096)][int]$KeyLength = 2048,
    [switch]$Enroll2SmartCard
)

if ($psISE) {
    $ScriptPath = Split-Path -Parent -Path $psISE.CurrentFile.FullPath
} else {
    $ScriptPath = Split-Path (Get-Variable MyInvocation).Value.MyCommand.Path
}

$Now = $(Get-Date -f yyyyMMdd-HHmmss)
$Logfile = "$($ScriptPath)\AzureManagedHSM-KeyCreation-$($subject)-$($Now).log"
If (!$FilePath) {
    $FilePath = "$env:USERPROFILE\Documents"
}

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

##
## main program starts here
##

$KeyAlgo = "RSA"

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

    $pswindow.windowtitle = "Azure Managed HSM Key Creation Ceremony"
    $pswindow.foregroundcolor = "White"
    $pswindow.backgroundcolor = "Black"
}

#endregion

#we assume all goes well
$failed = $false

Write-Message -Message "########################################################"
Write-Message -Message "Starting Key Creation Ceremony at: $(Get-Date)"
if (!$Subject) {
    Write-Message -Message " "
    Write-Message -Message "No enrollment subject specified!"

    $options = [System.Management.Automation.Host.ChoiceDescription[]] @("&Yes", "&No")
    [int]$defaultchoice = 1
    $exitLoop = $false
    do {
        $Subject = Read-Host -Prompt "Please specify enrollment subject"
        $choice = $host.UI.PromptForChoice("", "Use enrollment subject $($Subject)", $Options, $defaultchoice)

        switch($choice)
        {
            0 { $exitLoop = $true}
            #1 { Write-Host "No - Write your code"}
        }

    } while (!$exitLoop)
    Write-Message -Message " "
}

Write-Message -Message "Creating Key for enrollment subject: $($Subject)"
if ($Enroll2SmartCard) {
    Write-Message -Message "  Enrolling keys to smart card!"
    Write-Message -Message "  "
    Write-Message -Message "  The smart card MUST already be prepared for usage!"
    read-host -prompt "  Ensure, the smart card is inserted into the reader before continuing ...`n`r  --> PRESS ENTER WHEN READY" |out-null
    Write-Message -Message "  "
} else {
    Write-Message -Message "  Enrolling keys in software!"
} 
Write-Message -Message "Key files storage location: $($FilePath)"
Write-Message -Message "Existing files at $($FilePath) for $($Subject) will be overwritten!!!"
Write-Message -Message " checking for key files at $($FilePath)..."

$CertExportFileName = "$($FilePath)\$($Subject)"
if (Test-Path "$($CertExportFileName).*") {
    Write-Message -Message " "
    Write-Message -Message "Key files found at $($FilePath) for $($Subject) --> deleting ..."
    try {
        remove-item "$($CertExportFileName).*" -force -Verbose 4>&1 | out-file $logFile -Append
        Write-Message -Message "Key files deleted!" -Type Success
    } catch {
        Write-Message -Message " Could not delete key files at $($FilePath) for $($Subject)!" -Type Failure
        Write-Message -Message " Deletion failed with error:`r`n$($_.Exception.Message)`r`n`r`nAborting ..." -Type Failure
        $failed = $true
    }
} else {
    Write-Message -Message "No previously created key files found at $($FilePath) for $($Subject)" -Type Success
}

if (!$failed) {
    if ($Enroll2SmartCard) {
        $params = @{
            Type = 'Custom'
            Provider = 'Microsoft Smart Card Key Storage Provider'
            Subject = $Subject
            TextExtension = @(
                '2.5.29.37={text}1.3.6.1.5.5.7.3.2')
            KeyExportPolicy = 'NonExportable'
            KeyUsage = 'DigitalSignature'
            KeyAlgorithm = $KeyAlgo
            KeyLength = $keylength
            CertStoreLocation = 'Cert:\CurrentUser\My'
            NotAfter = (Get-Date).AddYears($ValidityTime) 
            FriendlyName = "$Subject"
        }
    } else {
        $params = @{
            TextExtension = @(
                '2.5.29.37={text}1.3.6.1.5.5.7.3.2')
            Subject = $Subject 
            CertStoreLocation = "Cert:\CurrentUser\My" 
            KeySpec = 'Signature' 
            KeyAlgorithm = $KeyAlgo
            KeyLength  = $KeyLength 
            KeyExportPolicy = 'Exportable' 
            NotAfter = (Get-Date).AddYears($ValidityTime) 
            FriendlyName = "$Subject"
        }
    }
    Write-Message -Message "Key parameters:"
    Write-Message -Message " Key algorithm: $($KeyAlgo)"
    Write-Message -Message " Key length: $($KeyLength)"
    Write-Message -Message " Validity: $($ValidityTime) years"

    Write-Message -Message "starting key creation ..."
    #create certificate
    try {
        $cert = New-SelfSignedCertificate @params -ErrorAction stop
        Write-Message -Message " Keys successfully created!" -Type Success
    } catch {
        Write-Message -Message " Keys creation failed with error:`r`n$($_.Exception.Message)`r`n`r`nAborting ..." -Type Failure
        $failed = $true
    } 
    if (!$failed) {
        Write-Message -Message "exporting public key as certificate ..."
        #Export the certificate and private key to a DER encoded cer
        try {
            Export-Certificate -Cert $cert -FilePath "$($CertExportFileName).cer" -ErrorAction stop
            certutil -encode -f "$($CertExportFileName).cer" "$($CertExportFileName).pem"
            Write-Message -Message " Public key successfully exported as $($CertExportFileName).pem!" -Type Success
        } catch {
            Write-Message -Message " Export of public key failed with error:`r`n$($_.Exception.Message)`r`n`r`nAborting ..." -Type Failure
            $failed = $true
        }
        
        if ((!$failed) and (!$Enroll2SmartCard)) {
            Write-Message -Message "creating PKCS12 protected key file ..."
            #create password for p12 file
            $exitLoop = $false
            do {
                $pwd1 = Read-Host -Prompt "Enter password to protect the PFX file" -AsSecureString
                $pwd2 = Read-Host -Prompt "Re-enter password" -AsSecureString
                if((Decrypt-SecString -SecStr $pwd1) -ne (Decrypt-SecString -SecStr $pwd2)) {
                    Write-Message -Message " The passwords do not match - please try again ..."
                } else {
                    $exitLoop = $true
                }
            } while (!$exitLoop)
            Write-Message -Message " writing keys to file ..."
            #Export the certificate and private key to a PFX file
            try {
                Export-PfxCertificate -Cert $cert -CryptoAlgorithmOption AES256_SHA256 -FilePath "$($CertExportFileName).pfx" -Password $pwd1 -Force -ErrorAction stop
                Write-Message -Message " Protected PKCS12 file successfully written as $($CertExportFileName).pfx!" -Type Success
            } catch {
                Write-Message -Message " Writing keys to protected PKCS12 file failed with error:`r`n$($_.Exception.Message)`r`n`r`nAborting ..." -Type Failure
                $failed = $true
            }
            $pwd1 = $null
            $pwd1 = $null
            Write-Message -Message " removing keys from local cert store ..."
            try {
                remove-item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -deletekey -force -Verbose 4>&1 | out-file $logFile -Append
                Write-Message -Message "Successfully removed keys from local cert store!" -Type Success
            } catch {
                Write-Message -Message "Removed keys from local cert store failed with error:`r`n$($_.Exception.Message)`r`n`r`n" -Type Failure
                Write-Message -Message "Please remove 'Cert:\CurrentUser\My\$($cert.Thumbprint)' manually..." -Type failure
            }
        }
    }
}

Write-Message -Message "#################################################################"
Write-Message -Message " "
if ($failed) {
    Write-Message -Message " Azure Managed HSM Key Creation Ceremony failed !" -Type Failure
    Write-Message -Message " Review errors messages and correct any issue before continuing !" -Type Failure
} else {
    Write-Message -Message " Azure Managed HSM Key Creation Ceremony completed successfully !" -Type Success
    if (!$Enroll2SmartCard) {
        Write-Message -Message " Please ensure that you are keeping the keys in a secure place" -Type Success
        Write-Message -Message " and properly protected." -Type Success
        Write-Message -Message " NEVER GIVE ANYONE ELSE ACCESS TO YOUR KEYS." -Type Success
        Write-Message -Message " "
        Write-Message -Message " Store your password in an sealed and enveloped letter for emergencies!" -Type Success
    } else {
        Write-Message -Message " Private key is enrolled in smart card crypto hardware" -Type Success
        Write-Message -Message " and protected by smart card PIN." -Type Success
        Write-Message -Message " "
    }
}
Write-Message -Message " "
Write-Message -Message "#################################################################"
