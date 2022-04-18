#PowerShell module for VMware VMDSC Fling
#Contributions, Improvements &/or Complete Re-writes Welcome!
#https://github.com/HeathReynolds/PowerVMDSC

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

#Revision - This module is updated to work with VMDSC version 1.1

$PSDefaultParameterValues["Add-VMDSC:cores"]="1"
$PSDefaultParameterValues["Set-VMDSC:cores"]="1"

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
    
    $Global:base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password))) # Create Basic Authentication Encoded Credentials
    $Global:fqdn = $vmdsc

    $headers = @{"Accept" = "application/json" }
    $headers.Add("Authorization", "Basic $base64AuthInfo")
    $uri = "https://"+$fqdn+":8010/auth/login" # Set URI for executing an API call to validate authentication

    Try {
        # Auth for Powershell Core (Store session ID as global variable)
        if ($PSEdition -eq 'Core') {
            $response = Invoke-RestMethod -Method POST -Uri $uri -Headers $headers
            $Global:vmdscsessionid1 = $response.SessionID
        }
        # Auth for Powershell Desktop (Store session ID as global variable)
        else {
            $response = Invoke-RestMethod -Method POST -Uri $uri -Headers $headers
            $Global:vmdscsessionid1 = $response.SessionID
        }
        if ($response.SessionID -match "local/sdk") {
            Write-Output "The connection between VMDSC and vCenter timed out, please try again"
        }
        if ($response.SessionID -match "[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}") {
            Write-Output "Successfully Requested New API Token From VMDSC: $fqdn"
        }
    }
    Catch {
        if($_.ErrorDetails.Message) {
            Write-Output $_.ErrorDetails.Message
        } else {
            Write-Output $_
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

    $uri = "https://"+$fqdn+":8010/configs" # Set URI for executing an API call to to read configs

    Try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers @{'session-id' = $Global:vmdscsessionid1}
        if ($response.uuid -match "[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}") {
            $response
        }
        else {
            Write-Output "No pending configurations found"
        }
    }
    Catch {
        if($_.ErrorDetails.Message) {
            Write-Output $_.ErrorDetails.Message
        } else {
            Write-Output $_
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
        $uri = "https://"+$fqdn+":8010/config/$uuid" # Set URI for executing an API call to a specific VM configuration
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers @{'session-id' = $Global:vmdscsessionid1}
        $response
        }
    Catch {
        if($_.ErrorDetails.Message) {
            Write-Output $_.ErrorDetails.Message
        } else {
            Write-Output $_
    }
    }
}
Export-ModuleMember -Function Get-VMDSC

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
    
    [CmdletBinding(DefaultParameterSetName="prompt")]

    param 
    (
        [Parameter(Mandatory=$true,ParameterSetName='defined')]
        [String] $uuid,
        [Parameter(Mandatory=$true,ParameterSetName='prompt')]
        [String] $promptuuid,
        [Parameter(Mandatory=$false,ParameterSetName='defined')]
        [Parameter(Mandatory=$true,ParameterSetName='prompt')]
        [int] $mem,
        [Parameter(Mandatory=$false,ParameterSetName='defined')]
        [Parameter(Mandatory=$true,ParameterSetName='prompt')]
        [int] $cpu,
        [Parameter(Mandatory=$false,ParameterSetName='defined')]
        [Parameter(Mandatory=$true,ParameterSetName='prompt')]
        [int] $cores
    )

    Try {
        $JSON = @{
            "uuid" = "$uuid+$promptuuid"
            "cpu" = $cpu
            "memsize" = $mem
            "cores_per_socket" = $cores
        } | ConvertTo-Json
        $uri = "https://"+$fqdn+":8010/config" # Set URI for executing an API call to a specific VM configuration
        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers @{'session-id' = $Global:vmdscsessionid1} -Body $JSON -ContentType "application/json"
        $response
        }
    Catch {
        if($_.ErrorDetails.Message) {
            Write-Output $_.ErrorDetails.Message
        } else {
            Write-Output $_
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
        $uri = "https://"+$fqdn+":8010/config/$uuid" # Set URI for executing an API call to a specific VM configuration
        $response = Invoke-RestMethod -Uri $uri -Method Delete -Headers @{'session-id' = $Global:vmdscsessionid1}
        $response
        }
    Catch {
        if($_.ErrorDetails.Message) {
            Write-Output $_.ErrorDetails.Message
        } else {
            Write-Output $_
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
    

    [CmdletBinding(DefaultParameterSetName='prompt')]
    
    param 
    (
        [Parameter(Mandatory=$true,ParameterSetName='defined')]
        [Parameter(Mandatory=$true,ParameterSetName='prompt')]
        [string] $uuid,
        [Parameter(Mandatory=$false,ParameterSetName='defined')]
        [Parameter(Mandatory=$true,ParameterSetName='prompt')]
        [int] $mem,
        [Parameter(Mandatory=$false,ParameterSetName='defined')]
        [Parameter(Mandatory=$true,ParameterSetName='prompt')]
        [int] $cpu,
        [Parameter(Mandatory=$false,ParameterSetName='defined')]
        [Parameter(Mandatory=$true,ParameterSetName='prompt')]
        [int] $cores
    )
    

    Try {
        $JSON = @{
            "cpu" = $cpu
            "memsize" = $mem
            "cores_per_socket" = $cores
        } | ConvertTo-Json
        $uri = "https://"+$fqdn+":8010/config/$uuid" # Set URI for executing an API call to a specific VM configuration
        $response = Invoke-RestMethod -Uri $uri -Method Put -Headers @{'session-id' = $Global:vmdscsessionid1} -Body $JSON -ContentType "application/json"
        $response
        }
    Catch {
        if($_.ErrorDetails.Message) {
            Write-Output $_.ErrorDetails.Message
        } else {
            Write-Output $_
    }
    }
}

Export-ModuleMember -Function Set-VMDSC
