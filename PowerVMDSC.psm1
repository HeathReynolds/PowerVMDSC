#PowerShell module for VMware VMDSC Fling
#Contributions, Improvements &/or Complete Re-writes Welcome!
#https://github.com/PowerVMDSC/PowerVMDSC

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

### Note
#This powershell module should be considered entirely experimental. It is still
#in development & not tested beyond lab scenarios.
#It is recommended you dont use it for any production environment
#without testing extensively!


# Enable communication with self signed certs when using Powershell Core
# If you require all communications to be secure and do not wish to
# allow communication with self signed certs remove lines 31-52 before
# importing the module

#This module is tested with Powershell Core 7.0 LTS on Windows Server 2016.
#It does not work on earlier Windows versions (We tested on 2012r2 and it didn't work) 
#due to weak cipher suite support for TLS 1.2.

if ($PSEdition -eq 'Core') {
    $PSDefaultParameterValues.Add("Invoke-RestMethod:SkipCertificateCheck", $true)
}

if ($PSEdition -eq 'Desktop') {
    # Enable communication with self signed certs when using Windows Powershell
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

    add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertificatePolicy : ICertificatePolicy {
        public TrustAllCertificatePolicy() {}
        public bool CheckValidationResult(
            ServicePoint sPoint, X509Certificate certificate,
            WebRequest wRequest, int certificateProblem) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertificatePolicy
}

function Connect-VMDSC {
    <#
        .SYNOPSIS
        Connects to the specified VMDSC and vCenter and requests access tokens

        .DESCRIPTION
        The Connect-VMDSC cmdlet connects to the specified VMDSC and vCenter and requests API tokens.
        It is required once per session before running all other cmdlets

        .EXAMPLE
        PS C:\> Connect-VMDSC -vmdsc vmdsc.sfo.rainpole.io -vcenter -username administrator@vsphere.local -password VMw@re1!
        This example shows how to connect to VMDSC
      #>
    param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vmdsc,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$username,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$password
    )
    
    if ( -not $PsBoundParameters.ContainsKey("username") -or ( -not $PsBoundParameters.ContainsKey("password"))) {
        $creds = Get-Credential # Request Credentials
        $username = $creds.UserName.ToString()
        $password = $creds.GetNetworkCredential().password
    }
    
    $uri = "https://"+$vmdsc+":8010/auth/login" # Set URI for executing an API call to validate authentication

    Try {
        # Checking authentication with VMDSC
        if ($PSEdition -eq 'Core') {
            $response = Invoke-RestMethod -Method POST -Uri $uri -SslProtocol TLS12 -Authentication Basic -Credential $creds
            $Global:vmdscsessionid1 = $response.SessionID
        }
        else {
            $response = Invoke-RestMethod -Method POST -Uri $uri -SslProtocol TLS12 -Authentication Basic -Credential $creds
            $Global:vmdscsessionid1 = $response.SessionID
        }
        if ($response.SessionID -match "-") {
            Write-Output "Successfully Requested New API Token From VMDSC: $vmdsc"
        }
        if ($response.SessionID -match "connection") {
            Write-Output "The connection between VMDSC and vCenter timed out, please try again"
        }
    }
    Catch {
        if($_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message
        } else {
            Write-Host $_
    }
}
}

Export-ModuleMember -Function Connect-VMDSC

function Get-VMDSCAll {
    <#
        .SYNOPSIS
        Reads all pending desired state configurations in the VMDSC database.

        .DESCRIPTION
        The Get-VMDSCAll cmdlet connects to the VMDSC instance and returna all configurations in the VMDSC database.
        An existing API token is required, please connect with Connect-VMDSC first.

        .EXAMPLE
        PS C:\> Get-VMDSCAll
      #>

    Try {
        $uri = "https://"+$vmdsc+":8010/configs" # Set URI for executing an API call to to read configs
        $response = Invoke-RestMethod -Uri $uri -Method Get -SslProtocol Tls12 -Headers @{'session-id' = $Global:vmdscsessionid1}
        $response
        }
    Catch {
        if($_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message
        } else {
            Write-Host $_
    }
    }
}

Export-ModuleMember -Function Get-VMDSCAll

function Get-VMDSC {
    <#
        .SYNOPSIS
        Reads the pending desired state config for a specific VM

        .DESCRIPTION
        The Get-VMDSC cmdlet connects to the VMDSC instance and returns the pending configuration for a specific VM.
        An existing API token is required, please connect with Connect-VMDSC first.

        .EXAMPLE
        PS C:\> Get-vmdsc -uuid 420377f7-bceb-d929-912b-6706e5debc71
      #>
    param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$uuid
    )
    
    Try {
        $uri = "https://"+$vmdsc+":8010/config/$uuid" # Set URI for executing an API call to a specific VM configuration
        $response = Invoke-RestMethod -Uri $uri -Method Get -SslProtocol Tls12 -Headers @{'session-id' = $Global:vmdscsessionid1}
        $response
        }
    Catch {
        if($_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message
        } else {
            Write-Host $_
    }
    }
}

function Add-VMDSC {
    <#
        .SYNOPSIS
        Adds the pending desired state config for a specific VM

        .DESCRIPTION
        The Add-VMDSC cmdlet connects to the VMDSC instance and sets a pending configuration for a specific VM.
        An existing API token is required, please connect with Connect-VMDSC first.

        .EXAMPLE
        PS C:\> Add-vmdsc -uuid 420377f7-bceb-d929-912b-6706e5debc71n -cpu 2 -mem 4096
      #>
    param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$uuid,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [int]$mem,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [int]$cpu
    )
    
    Try {
        $JSON = @{
            "uuid" = "$uuid"
            "cpu" = $cpu
            "memsize" = $mem
        } | ConvertTo-Json
        $uri = "https://"+$vmdsc+":8010/config" # Set URI for executing an API call to a specific VM configuration
        $response = Invoke-RestMethod -Uri $uri -Method Post -SslProtocol Tls12 -Headers @{'session-id' = $Global:vmdscsessionid1} -Body $JSON -ContentType "application/json"
        $response
        }
    Catch {
        if($_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message
        } else {
            Write-Host $_
    }
    }
}

Export-ModuleMember -Function Add-VMDSC

function Clear-VMDSC {
    <#
        .SYNOPSIS
        Clears the pending desired state config for a specific VM

        .DESCRIPTION
        The Clear-VMDSC cmdlet connects to the VMDSC instance and clears the pending configuration for a specific VM.
        An existing API token is required, please connect with Connect-VMDSC first.

        .EXAMPLE
        PS C:\> Clear-vmdsc -uuid 420377f7-bceb-d929-912b-6706e5debc71
      #>
    param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$uuid
    )
    
    Try {
        $uri = "https://"+$vmdsc+":8010/config/$uuid" # Set URI for executing an API call to a specific VM configuration
        $response = Invoke-RestMethod -Uri $uri -Method Delete -SslProtocol Tls12 -Headers @{'session-id' = $Global:vmdscsessionid1}
        $response
        }
    Catch {
        if($_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message
        } else {
            Write-Host $_
    }
    }
}
Export-ModuleMember -Function Clear-VMDSC

function Set-VMDSC {
    <#
        .SYNOPSIS
        Updates the pending desired state config for a specific VM

        .DESCRIPTION
        The Set-VMDSC cmdlet connects to the VMDSC instance and updates an exiting pending 
        configuration for a specific VM.
        An existing API token is required, please connect with Connect-VMDSC first.

        .EXAMPLE
        PS C:\> Set-vmdsc -uuid 420377f7-bceb-d929-912b-6706e5debc71n -cpu 2 -mem 4096
      #>
    param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$uuid,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [int]$mem,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [int]$cpu
    )
    
    Try {
        $JSON = @{
            "cpu" = $cpu
            "memsize" = $mem
        } | ConvertTo-Json
        $uri = "https://"+$vmdsc+":8010/config/$uuid" # Set URI for executing an API call to a specific VM configuration
        $response = Invoke-RestMethod -Uri $uri -Method Put -SslProtocol Tls12 -Headers @{'session-id' = $Global:vmdscsessionid1} -Body $JSON -ContentType "application/json"
        $response
        }
    Catch {
        if($_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message
        } else {
            Write-Host $_
    }
    }
}

Export-ModuleMember -Function Set-VMDSC