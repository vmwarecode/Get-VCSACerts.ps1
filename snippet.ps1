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