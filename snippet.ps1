<#
    .NOTES
        Author: Mark McGill, VMware
        Last Edit: 9-1-2020
        Version 1.1
    .SYNOPSIS
        Returns vCenter certificate information for all VCSA certificates, and optionally returns host certs
    .DESCRIPTION
        Returns valid from and valid to dates for all VCSA certificates, including STS Signing Certs. 
        See https://kb.vmware.com/s/article/79248
        vCenter and user are required. If no password is specified, you will be prompted for one
        USER MUST BE A VCENTER LOCAL USER (ie, administrator@vsphere.local), AND MUST BE IN SPN FORMAT (ie, user@domain.com)
    .EXAMPLE
        #load function and run
        . ./Get-VCSACerts.ps1
        Get-STSCerts -vcenter "vcenter.domain.com" -user "administrator@vsphere.local" -password 'VMware1!'
    .EXAMPLE
        #uses an array to pass multiple vcenters to the function
        $vCenters = "vCenter1.domain.com","vcenter2.domain.com","vCenter3.domain.com"
        $vCenters | Get-VCSACerts -user "administrator@vsphere.local" -password 'VMware1!'
    .EXAMPLE
        #use the '-includeHosts' option to get all host certificates
        Get-VCSACerts -vcenter "vcenter.domain.com" -user "administrator@vsphere.local" -includeHosts
    .EXAMPLE
        #use the '-unique' option to filter duplicate certificates
        Get-VCSACerts -vcenter "vcenter.domain.com" -user "administrator@vsphere.local" -unique
    .EXAMPLE
        #use the '-Verbose' option to show connection and retrieval details
        Get-VCSACerts -vcenter "vcenter.domain.com" -user "administrator@vsphere.local" -unique
    .OUTPUTS
        Array of objects containing certificate data
#>

function Get-VCSACerts
{
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]$vcenters,
        [Parameter(Mandatory=$true)]$user,
        [Parameter(Mandatory=$false)]$password,
        [Parameter(Mandatory=$false)][switch]$includeHosts,
        [Parameter(Mandatory=$false)][switch]$unique
    )
    Begin
    {
        Try
        {
            $userName = $user.Split("@")[0]
            $domain = ($user.Split("@")[1]).Split(".")
            $userDn = "cn=$userName,cn=users,dc=$($domain[0]),dc=$($domain[1])"
            $baseDn = "dc=$($domain[0]),dc=$($domain[1])"
    
            If($password -eq $null)
            {
                $securePassword = Read-Host -Prompt "Enter password for administrator account (ie: administrator@vsphere.local)" -AsSecureString
            }
            Else
            {
                $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
            }
            $ldapCreds = New-Object System.Management.Automation.PSCredential -ArgumentList $userDN, $securePassword -ErrorAction Stop
        }
        Catch
        {
            Throw "Error creating credentials for LDAP: $($_.Exception.Message)"
        }
        $certificates = @()
    } #end Begin

    Process
    {
        foreach($vcenter in $vcenters)
        {

            [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
            $ldapConnect = New-Object System.DirectoryServices.Protocols.LdapConnection $vcenter
            $ldapConnect.SessionOptions.SecureSocketLayer = $false
            $ldapConnect.SessionOptions.ProtocolVersion = 3
            $ldapConnect.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic

            Try 
            {
                $ErrorActionPreference = 'Stop'
                $ldapConnect.Bind($ldapCreds)
                $ErrorActionPreference = 'Continue'
                Write-Verbose "Successfully connected to LDAP"
            }
            Catch 
            {
                Throw "Error binding to LDAP on $vcenter : $($_.Exception.Message)"
            }

            $scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
            $query = New-Object System.DirectoryServices.Protocols.SearchRequest 
            $query.DistinguishedName = $baseDN
            $query.Filter = "(&(userCertificate=*)(!(objectClass=STSTenantTrustedCertificateChain)))"
            $query.Attributes.Add("userCertificate") | Out-Null
            $query.Attributes.Add("objectClass") | Out-Null

            Try 
            {
                $ErrorActionPreference = 'Stop'
                $request = $ldapConnect.SendRequest($query) 
                $ErrorActionPreference = 'Continue'
                Write-Verbose "Successfully sent query to LDAP"
            }
            Catch 
            {
                Throw "Error sending LDAP request - $($_.Exception.Message)"
            }

            $services = $request.Entries
            Write-Verbose "Query returned $($services.Count) services"
            foreach ($service in $services)
            {
                $objectClasses = $service.Attributes['objectClass']
                foreach ($objectClass in $objectClasses)
                {
                    $convert = [System.Text.Encoding]::ASCII.GetString($objectClass)
                    If ($convert -match "vmw")
                    {
                        $type = $convert.Replace("vmw","")
                    }
                }#end foreach objectClass

                $serviceCerts = $service.Attributes['userCertificate']
                Write-Verbose "Service $type has $($serviceCerts.Count) certificates"
                foreach ($cert in $serviceCerts)
                {
                    $certificate = "" | Select vCenter,Type,Subject,ValidFrom,ValidTo,Issuer,Thumbprint
                    $X509Cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,([byte[]]$cert))
                    $certificate.vCenter = $vCenter
                    $certificate.Type = $type
                    $certificate.Subject = (($X509Cert.Subject).Split(",")[-1]).Split("=")[-1]
                    $certificate.ValidFrom = $X509Cert.NotBefore
                    $certificate.ValidTo = $X509Cert.NotAfter
                    $certificate.Issuer = $X509Cert.Issuer
                    $certificate.Thumbprint = $X509Cert.Thumbprint
                    $certificates += $certificate
                }#end foreach $cert
            }#end foreach service
            #filter duplicate certs sort by Type
            If ($unique -eq $true)
            {
                Write-Verbose "Filtering for unique certificates"
                $certificates = $certificates | Sort-Object -Property Type | Sort-Object -Property Thumbprint -Unique
            }
            
            #gets host certificates if -includeHosts is specified
            If ($includeHosts)
            {
                Write-Verbose "Retrieving host certificate information"
                If ($global:DefaultVIServer.Name -ne $vCenter -or $global:DefaultVIServer.IsConnected -eq $false)
                {
                    Try
                    {
                        $vCenterCreds = New-Object System.Management.Automation.PSCredential -ArgumentList $user,$securePassword -ErrorAction Stop
                        Connect-VIServer $vcenter -Credential $vCenterCreds -ErrorAction Stop | Out-Null
                        Write-Verbose "Successfully connected to $vCenter using existing credentials"
                    }
                    Catch
                    {
                        Connect-VIServer $vcenter
                        Write-Verbose "Successfully connected to $vCenter"
                    }
                }
                Try
                {
                    $vmHosts = Get-View -ViewType HostSystem -Property Name,Config.Certificate -Server $vCenter -ErrorAction Stop
                }
                Catch
                {
                    Throw "Error getting host information from $vCenter - $($_.Exception.Message)"
                }
                Write-Verbose "Getting certificates from $($vmHosts.Count) hosts"
                Write-Verbose "$($vmHosts.Name)"
                Try
                {
                    foreach ($vmHost in $vmHosts)
                    {
                        $cert = $vmHost.Config.Certificate
                        $certificate = "" | Select vCenter,Type,Subject,ValidFrom,ValidTo,Issuer,Thumbprint
                        $X509Cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,([byte[]]$cert)) -ErrorAction Stop
                        $certificate.vCenter = $vCenter
                        $certificate.Type = "Host"
                        $certificate.Subject = $vmHost.Name
                        $certificate.ValidFrom = $X509Cert.NotBefore
                        $certificate.ValidTo = $X509Cert.NotAfter
                        $certificate.Issuer = $X509Cert.Issuer
                        $certificate.Thumbprint = $X509Cert.Thumbprint
                        $certificates += $certificate
                    }#end foreach vmHost
                }
                Catch
                {
                    Throw "Error retrieving certificate information from $($vmHost.Name) - $($_.Exception.Message)"
                }
                If ($vCenterCreds -ne $null)
                {
                    Remove-Variable vCenterCreds
                }
            }#end if
        }#end foreach vCenter
    }#end Process
    End
    {
        Remove-Variable ldapConnect
        Remove-Variable securePassword
        Remove-Variable ldapCreds
        $certificates = $certificates | Sort-Object -Property Type -Descending
        Return $certificates
    }
}