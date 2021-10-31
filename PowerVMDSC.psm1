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
#It does not work on earlier Windows versions (Tested on 2012r2) due to weak
#cipher suite support for TLS 1.2.

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
    


}