<#
    .NOTES
        Author: Mark McGill, VMware
        Last Edit: 5/6/2022
        Version 1.4
    .SYNOPSIS
        Returns vCenter certificate information for all VCSA certificates, and optionally returns host certs
    .DESCRIPTION
        Returns valid from and valid to dates for all VCSA certificates, including STS Signing Certs. 
        See https://kb.vmware.com/s/article/79248
        vCenter and user are required. If no password is specified, you will be prompted for one
        USER MUST BE A VCENTER LOCAL USER (ie, administrator@vsphere.local), AND MUST BE IN SPN FORMAT (ie, user@domain.com)
    .PARAMETER vcenters
        REQUIRED
        A single vCenter or array of vCenters to query
    .PARAMETER user
        REQUIRED
        vSphere local domain user in SPN format (ie, administrator@vsphere.local). Local user is needed in order to query LDAP
    .PARAMETER password
        If you do not specify a password when calling the function, you will be prompted for it
    .PARAMETER includeHosts
        Using this flag will retrieve certs from each host associated with the vCenter(s)
    .PARAMETER all
        Using this flag will return "STSRelyingParty" and "STSTenantTrustedCertificateChain" certificates, which are normally duplicates of already
            reported certificates
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
        #use the '-all' option to include "STSRelyingParty" and "STSTenantTrustedCertificateChain" certificates
        Get-VCSACerts -vcenter "vcenter.domain.com" -user "administrator@vsphere.local" -all
    .EXAMPLE
        #use the '-Verbose' option to show connection and retrieval details
            Get-VCSACerts -vcenter "vcenter.domain.com" -user "administrator@vsphere.local" -Verbose
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
        [Parameter(Mandatory=$false)][switch]$all
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
                $securePassword = Read-Host -Prompt "Enter password for administrator account" -AsSecureString
            }
            Else
            {
                $securePassword = ConvertTo-SecureString -String $password -AsPlainText -Force
                Clear-Variable password
            }
    
            #create credentials for rest api
            $restAuth = $user + ":" + $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)))
            $encoded = [System.Text.Encoding]::UTF8.GetBytes($restAuth)
            $encoded=[System.Text.Encoding]::UTF8.GetBytes($restAuth)
            $encodedAuth=[System.Convert]::ToBase64String($encoded)
            $headersAuth = @{"Authorization"="Basic $($encodedAuth)"}
            #create credentials for ldap auth
            $ldapCreds = New-Object System.Management.Automation.PSCredential -ArgumentList $userDN, $securePassword -ErrorAction Stop
        }
        Catch
        {
            Throw "Error creating authentication: $($_.Exception.Message)"
        }
        $certificates = @()
    } #end Begin

    Process
    {
        foreach($vcenter in $vcenters)
        {
            #query vCenter rest api for machine_cert
            $uriAuth = "https://$vcenter/rest/com/vmware/cis/session"
            $uriTls = "https://$vcenter/rest/vcenter/certificate-management/vcenter/tls"
            try 
            {
                $sessionId = (Invoke-RestMethod -Uri $uriAuth -Method Post -Headers $headersAuth -SkipCertificateCheck -ErrorAction Stop).Value
                $tlsHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                $tlsHeaders.Add("vmware-api-session-id", "$sessionId")
                $machineCert = (Invoke-RestMethod -Uri $uriTls -Method Get -Headers $tlsHeaders -SkipCertificateCheck -ErrorAction Stop).Value
                Write-Verbose "Successfully queried $vcenter API"
            }
            #catch to skip certificate errors in Powershell 5.x
            Catch [System.Management.Automation.RuntimeException]
            {
                add-type @"
                using System.Net;
                using System.Security.Cryptography.X509Certificates;
                public class TrustAllCertsPolicy : ICertificatePolicy {
                    public bool CheckValidationResult(
                        ServicePoint srvPoint, X509Certificate certificate,
                        WebRequest request, int certificateProblem) {
                        return true;
                    }
                }
"@
                [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                $sessionId = (Invoke-RestMethod -Uri $uriAuth -Method Post -Headers $headersAuth -ErrorAction Stop).Value
                $tlsHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
                $tlsHeaders.Add("vmware-api-session-id", "$sessionId")
                $machineCert = (Invoke-RestMethod -Uri $uriTls -Method Get -Headers $tlsHeaders -ErrorAction Stop).Value
                Write-Verbose "Successfully queried $vcenter API 5"
            }
            Catch
            {
                Throw "Error querying $vcenter API: $($_.Exception.Message)"
            }
            Finally
            {
                $certificate = "" | Select vCenter,Type,Subject,ValidFrom,ValidTo,Issuer,Thumbprint
                $certificate.vCenter = $vcenter
                $certificate.Type = "MACHINE_CERT"
                $certificate.Subject = (($machineCert.subject_dn).Split(",")[-1]).Split("=")[-1]
                $certificate.ValidFrom = $machineCert.valid_from
                $certificate.ValidTo = $machineCert.valid_to
                $certificate.Issuer = $machineCert.issuer_dn
                $certificate.Thumbprint = $machineCert.thumbprint
                $certificates += $certificate
            }

            #retrieve certificate information from ldap
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

            $query = New-Object System.DirectoryServices.Protocols.SearchRequest 
            $query.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
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
            #filter out STSRelyingParty Certs
            If ($all -ne $true)
            {
                $certificates = $certificates | Where{$_.Type -ne "STSRelyingParty" -and $_.Type -ne "STSTenantTrustedCertificateChain"} | Sort-Object -Property Type
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
                    $vmHosts = Get-View -ViewType HostSystem -Property Name,Config.Certificate -Server $vCenter -Filter @{'Runtime.ConnectionState'='connected';'Runtime.PowerState'='poweredOn'} -ErrorAction Stop
                }
                Catch
                {
                    Throw "Error getting host information from $vCenter - $($_.Exception.Message)"
                }
                Write-Verbose "Getting certificates from $($vmHosts.Count) hosts"
                Write-Verbose "$($vmHosts.Name)"

                    foreach ($vmHost in $vmHosts)
                    {
                        Try
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
                            }
                        Catch
                        {
                            Write-Host "Error retrieving certificate information from $($vmHost.Name) - $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }#end foreach vmHost

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
        #Remove duplicate certificates - added for version 1.4
        $certificates = $certificates | Sort-Object -Property Thumbprint -Unique
        Return $certificates
    }
}