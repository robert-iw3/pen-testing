# Small script to check Exchange Version, Releasedate and Auth Realm
# Needs PS7+ / not compatible with PS5
# run with Get-ExchangeInfo -ServerUrl https://your.exchange or https://1.2.3.4
function Get-ExchangeVersionInfo {
    param (
        [string]$ServerUrl,
        [switch]$SkipCertificateCheck,   # Flag to skip certificate checks
        [switch]$SkipHttpErrorCheck      # Flag to skip HTTP error handling
    )

    # Display usage guide if no parameters are provided
    if (-not $ServerUrl -and -not $SkipCertificateCheck -and -not $SkipHttpErrorCheck) {
        Write-Host "Usage: Get-ExchangeVersionInfo -ServerUrl <URL> [-SkipCertificateCheck] [-SkipHttpErrorCheck]" -ForegroundColor DarkYellow
        Write-Host "" -ForegroundColor DarkYellow
        Write-Host "Parameters:" -ForegroundColor DarkYellow
        Write-Host "  -ServerUrl             The URL of the Exchange server to check." -ForegroundColor DarkYellow
        Write-Host "  -SkipCertificateCheck  (PowerShell 7+) Skips SSL certificate validation errors." -ForegroundColor DarkYellow
        Write-Host "  -SkipHttpErrorCheck    (PowerShell 7+) Allows to skip 401 errors and still fetch the headers." -ForegroundColor DarkYellow
        Write-Host "" -ForegroundColor DarkYellow
        Write-Host "Example:" -ForegroundColor DarkYellow
        Write-Host "  Get-ExchangeVersionInfo -ServerUrl 'https://my-exchangeserver' -SkipCertificateCheck" -ForegroundColor DarkYellow
        return
    }

    # Define the Microsoft Exchange build numbers page URL
    $buildNumbersPage = "https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates?view=exchserver-2019"

    # Initialize variable to store header version
    $headerVersion = $null

    # Flag to track if a match is found
    $foundMatch = $false

    try {
        # Prepare headers for the main request
        $requestParams = @{
            Uri     = "$ServerUrl/autodiscover/autodiscover.xml"
            Method  = 'Get'
            Headers = @{ "User-Agent" = "Mozilla/5.0" }
            UseBasicParsing = $true
        }

        # Apply certificate and error check overrides based on user input
        if ($SkipCertificateCheck) {
            $requestParams.SkipCertificateCheck = $true
        }
        if ($SkipHttpErrorCheck) {
            $requestParams.SkipHttpErrorCheck = $true
        }

        # Fetch the Exchange headers
        $response = Invoke-WebRequest @requestParams
        $headerVersion = $response.Headers["X-OWA-Version"]

        if ($headerVersion) {
            Write-Host "Exchange Version from header: $headerVersion"
        } else {
            Write-Host "X-OWA-Version header not found."
        }

        # Fetch MS build numbers page content
        $webContent = Invoke-WebRequest -Uri $buildNumbersPage -UseBasicParsing
        $contentText = $webContent.Content

        # Use regex to extract version information
        $trBlocks = [regex]::Matches($contentText, "<tr>(.*?)</tr>", [System.Text.RegularExpressions.RegexOptions]::Singleline)

        # Function to search for a match in build numbers for a given version
        function CheckForMatch {
            param ($versionToCheck, $blocks, [ref]$foundMatch)
        
            foreach ($block in $blocks) {
                $blockContent = $block.Groups[1].Value
        
                # Ensure we match the exact version
                if ($blockContent -match [regex]::Escape($versionToCheck)) {
        
                    # Extract Product Name (inside <a> tag, correctly stripping &nbsp;)
                    $productMatch = [regex]::Match($blockContent, '<a[^>]*>(.*?)</a>')
        
                    # Extract all <td> values (to correctly get the second <td> as Release Date)
                    $tdMatches = [regex]::Matches($blockContent, '<td[^>]*>(.*?)</td>')
        
                    # Extract the exact Build Number (not the long format)
                    $versionMatch = [regex]::Match($blockContent, '\d+\.\d+\.\d+\.\d+')
        
                    if ($productMatch.Success -and $versionMatch.Success -and $tdMatches.Count -ge 2) {
                        # Clean up Product Name (strip &nbsp; and trim spaces)
                        $product = $productMatch.Groups[1].Value -replace "&nbsp;", "" -replace "^\s+", "" -replace "", ""
        
                        # Get correct Release Date (the second <td> value)
                        $releaseDate = $tdMatches[1].Groups[1].Value.Trim()
        
                        # Extract version correctly
                        $version = $versionMatch.Value
        
                        # Output the exact match
                        Write-Host "`nMatch Found!" -ForegroundColor Green
                        Write-Host "Product: $product"
                        Write-Host "Build Number: $version"
                        Write-Host "Release Date: $releaseDate"
        
                        $foundMatch.Value = $true
                        break
                    }
                }
            }
        }

        # Check for matches with the header version
        if ($headerVersion) {
            Write-Host "`nChecking Microsoft build numbers page for header version..."
            CheckForMatch -versionToCheck $headerVersion -blocks $trBlocks -foundMatch ([ref]$foundMatch)
        }

        # Output if no match was found
        if (-not $foundMatch) {
            Write-Host "`nNo matching build number found for the version."
        }

    } catch {
        Write-Host "An error occurred: $_"
    }
}

# Function to extract the authentication domain
function Get-AuthDomain {
    param (
        [string]$ServerUrl  # Only the base server URL is needed
    )

    Write-Host "`nExtracting authentication domain from: $ServerUrl"

    $endpoints = @("/autodiscover/autodiscover.xml", "/EWS/Exchange.asmx")
    $authDomainFound = $false

    # Iterate over the endpoints
    foreach ($endpoint in $endpoints) {
        try {
            $url = "$ServerUrl$endpoint"
            # Write-Host "[*] Checking endpoint: $url"

            # Prepare request parameters with automatic certificate check bypass
            $requestParams = @{
                Uri     = $url
                Method  = 'Post'
                Headers = @{ "Authorization" = "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" }
                UseBasicParsing = $true
                SkipCertificateCheck = $true
            }

            # Invoke the web request
            $response = Invoke-WebRequest @requestParams -ErrorAction Stop 

        } catch {
            $response = $_.Exception.Response

            if ($response -and $response.StatusCode -eq [System.Net.HttpStatusCode]::Unauthorized) {
                # Enumerate headers to find 'WWW-Authenticate'
                foreach ($header in $response.Headers) {
                    if ($header.Key -eq "WWW-Authenticate") {
                        $authHeaderValue = $header.Value
                        $authHeaderTokens = $authHeaderValue -split ',|\s'
                        # Check if NTLM token is present
                        if ($authHeaderTokens.Length -gt 1) {
                            try {
                                # Decode the authentication header
                                $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($authHeaderTokens[1]))
                                $domainParts = $decoded -replace '[^\x21-\x39\x41-\x5A\x61-\x7A\x5F]+', ',' -split ','

                                if ($domainParts.Count -gt 7) {
                                    Write-Host "Authentication domain found: $($domainParts[4]) or $($domainParts[7])" -ForegroundColor Green
                                    $authDomainFound = $true
                                    break
                                } else {
                                    Write-Host "Could not extract domain information."
                                }
                            } catch {
                                Write-Host "Failed to decode authentication header."
                            }
                        } else {
                            Write-Host "NTLM token not found in the header value."
                        }
                    }
                }
            } else {
                Write-Host "Unexpected HTTP status code or no response received."
            }
        }

        # If the authentication domain was found, exit the loop
        if ($authDomainFound) { break }
    }

    # If no authentication domain was found after checking both endpoints
    if (-not $authDomainFound) {
        Write-Host "Could not retrieve authentication domain from either endpoint."
    }
}

# Main execution logic
function Get-ExchangeInfo {
    param (
        [string]$ServerUrl
    )

    if (-not $ServerUrl) {
        Write-Host "Missing required parameter: -ServerUrl" -ForegroundColor Red
        return
    }

    # Run Exchange Version Check
    Get-ExchangeVersionInfo -ServerUrl $ServerUrl -SkipCertificateCheck -SkipHttpErrorCheck

    # Run Authentication Domain Extraction on specified server
    Get-AuthDomain -ServerUrl $ServerUrl -SkipCertificateCheck -SkipHttpErrorCheck

    Write-Host "Scan Completed."
}
