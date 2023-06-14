function Import-CertToAgent {
    <#
	    .SYNOPSIS
	    Imports a certificate to a build agent to make connections to resources e.g. a Application Service Principal certificate to allow agent to authenticate to MSGraph
	    .DESCRIPTION
	    Return Certificate Thumbprint
        Pre-reqs:   
        - Uses Windows PKI module commands so only works on Windows Agent
        - Pfx certificate stored as Secure File in Variables Library downloaded to agent using the Download Secure File action https://docs.microsoft.com/en-us/azure/devops/pipelines/library/secure-files?view=azure-devops
        - Certificate Password best stored in Linked Azure Vault https://docs.microsoft.com/en-us/azure/devops/pipelines/library/variable-groups
	    .PARAMETER password
        [securestring] password of Pfx file
		.PARAMETER certDir
		[string] Path to pfx file downloaded onto agent typically $env:AGENT_TEMPDIRECTORY
		.PARAMETER certName
		[string] Name of certificate file downloaded to client include pfx file extension
		.PARAMETER certStore
		[string] Certificate store path for install on agent
	    .EXAMPLE
        $pass = ConvertTo-SecureString $env:SP_CERT_PASS -AsPlainText -Force    
        $thumbprint = Import-CertToAgent -password $pass -certDir $env:AGENT_TEMPDIRECTORY -certName 'servprin-ado-msgraph.pfx' -certStore 'Cert:\CurrentUser\My'
				
	    .INPUTS
	    
	    .OUTPUTS
        Return Certificate Thumbprint
	    .NOTES
	    .LINK
	#>

	Param (
		[Parameter(Mandatory=$true)]
		[securestring]$password,
		[Parameter(Mandatory=$true)]
		[string]$certDir,
		[Parameter(Mandatory=$true)]
		[string]$certName,
		[Parameter(Mandatory=$true)]
		[string]$certStore
	)
	



    Write-Host "Import Certificate"
    $certPath = Join-Path $certDir $certName

    Write-Host "Checking CertPass is connected Properly and Cert file path correct and downloaded"
    if(($null -eq $password) -or (!(Test-Path -path $certPath))){
        Write-Host "Cert or CertPass is NULL"
        Throw "Cert or CertPass is NULL"
    }
    Write-Host "CertPass and cert OK"

    Write-Host "Importing cert from $certPath into store $certStore"
    
    Import-PfxCertificate -FilePath $certPath -CertStoreLocation $certStore  -Password $password | Out-null
    
    # $certificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    # $certificateObject.Import($certPath, $password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet) | Out-null

	$certificateObject = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2($certPath, $password)
	[string]$thumbprint = $certificateObject.Thumbprint

    Return $thumbprint

}
