# Load VirusTotalAnalyzer module
Import-Module VirusTotalAnalyzer -Force

# Define API Key
$VTApi = 'fbe6f54afc05632834d509712b6ad75e3d6e592c9fe02f97039ed3d4aa4dbf87'

# Check if API Key is set
if (-not $VTApi) {
    Write-Error "API Key is not set. Please set your VirusTotal API key."
    exit
}

# Define the folder to scan
$FolderPath = "C:\Users\kunal.kumar\Downloads\reports"

# Check if folder exists
if (-not (Test-Path -Path $FolderPath)) {
    Write-Error "Folder path does not exist. Please provide a valid folder path."
    exit
}

# Get all files in the folder
$Files = Get-ChildItem -Path $FolderPath -File

foreach ($File in $Files) {
    try {
        Write-Output "Submitting file for scanning: $($File.FullName)"
        $Output = New-VirusScan -ApiKey $VTApi -File $File.FullName
        $Output | Format-List

        # Check if the scan was submitted successfully
        if ($Output -and $Output.data -and $Output.data.id) {
            Start-Sleep -Seconds 60

            # Retrieve the report using the scan ID
            try {
                $OutputScan = Get-VirusReport -ApiKey $VTApi -AnalysisId $Output.data.id
                # Print the entire structure of the output for inspection
                $OutputScan | Format-List -Force
                $OutputScan.Meta | Format-List -Force
                $OutputScan.Data | Format-List -Force

                # Additional checks to print results if available
                if ($OutputScan.Data.attributes.results) {
                    $OutputScan.Data.attributes.results | Format-List -Force
                } else {
                    Write-Output "No results found in the report."
                }
            } catch {
                Write-Error "Error retrieving virus report from VirusTotal: $_"
            }
        } else {
            Write-Error "Failed to submit the file for scanning. Please check your API key and file path."
        }
    } catch {
        Write-Error "Error submitting file to VirusTotal: $_"
    }
}
