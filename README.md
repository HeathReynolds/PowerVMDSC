# PowerVMDSC

PowerVMDSC is a powershell module to interact with the VMDSC Fling API ( https://flings.vmware.com/virtual-machine-desired-state-configuration )
It supports the following cmdlets : 
Connect-VMDSC (Connect to VMDSC API, get API key)
Get-VMDSCAll (List all pending changes)
Get-VMDSC (List pending changes for a specific change by VM UUID)
Clear-VMDSC (Clear pending changes by UUID)
Add-VMDSC (Add a desired state [CPU , MEM] by UUID)
Set-VMDSC (Update and existing desired state [CPU , MEM] by UUID)

There are known issues with Windows 2012r2 (using either Powershell Core or Powershell Desktop). VMDSC requires TLS 1.2 or 1.3 with a secure cipher set, the cipher sets supported by the Windows 2012r2 TLS 1.2 implementation are not compatible with VMDSC. Please use a more modern windows operating system supporting the following cipher sets :

Preferred TLSv1.3 128 bits TLS_AES_128_GCM_SHA256 Curve 25519 DHE 253

Accepted TLSv1.3 256 bits TLS_CHACHA20_POLY1305_SHA256 Curve 25519 DHE 253

Accepted TLSv1.3 256 bits TLS_AES_256_GCM_SHA384 Curve 25519 DHE 253

Preferred TLSv1.2 128 bits ECDHE-RSA-AES128-GCM-SHA256 Curve 25519 DHE 253

Accepted TLSv1.2 256 bits ECDHE-RSA-AES256-GCM-SHA384 Curve 25519 DHE 253

4/21/2022 - Updated to support VMDSC version 1.1 (PowerVMDSC version 1.1.0). 
Added support for cores per socket, pipeline uuid parameter
Updated to support VMDSC ver 1.1 API
