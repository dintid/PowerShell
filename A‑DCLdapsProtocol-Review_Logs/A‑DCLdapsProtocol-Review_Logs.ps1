# Function to write colored output to host
function Write-LogHost {
    param(
        [string]$Message,
        [ConsoleColor]$Color = 'White'
    )
    Write-Host $Message -ForegroundColor $Color
}

# Define event IDs and descriptions
$eventList = @(
    @{ Id = 4624; Description = "Successful Account Logon - Shows logons, filtered to those potentially affected by TLS changes" },
    @{ Id = 36887; Description = "Fatal TLS Alert - Indicates a fatal TLS protocol alert received from remote endpoint" },
    @{ Id = 36888; Description = "Warn TLS Alert - Indicates a warning TLS alert from remote endpoint" },
    @{ Id = 36889; Description = "TLS Handshake Failure - Handshake failure detected" }
)

foreach ($eventInfo in $eventList) {
    $eventId = $eventInfo.Id
    $eventDesc = $eventInfo.Description

    Write-Host "========================="
    Write-Host "Event ID: $eventId - $eventDesc"
    Write-Host "-------------------------"

    try {
        # For event 4624, prompt user for time range (default 1 hour)
        if ($eventId -eq 4624) {
            $defaultHours = 1
            $response = Read-Host "Look back how many hours for event ID $eventId? (default $defaultHours)"
            if ([string]::IsNullOrWhiteSpace($response)) {
                $hoursBack = $defaultHours
            }
            else {
                $hoursBack = [int]$response
            }
            $startTime = (Get-Date).AddHours(-$hoursBack)
            $filter = @{LogName='Security'; Id=$eventId; StartTime=$startTime}
        }
        else {
            # For other events, no time limit
            $filter = @{LogName='System'; Id=$eventId}
        }

        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop

        $countTotal = $events.Count

        if ($countTotal -eq 0) {
            # Instead of error, just output in yellow that no events found
            Write-LogHost "No events found for ID $eventId." -Color Yellow
        }
        else {
            Write-LogHost ("Total events found for ID {0}: {1}" -f $eventId, $countTotal) -Color Cyan

            # Show last 10 events
            $eventsToShow = $events | Select-Object -Last 10

            # Prepare table objects
            $table = foreach ($event in $eventsToShow) {
                $timeCreated = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                $summary = switch ($event.Id) {
                    4624 { "Successful Account Logon" }
                    36887 { "Fatal TLS Alert" }
                    36888 { "Warning TLS Alert" }
                    36889 { "TLS Handshake Failure" }
                    default { "Event" }
                }
                [PSCustomObject]@{
                    TimeCreated  = $timeCreated
                    Id           = $event.Id
                    Summary      = $summary
                    ComputerName = $event.MachineName
                }
            }

            $table | Format-Table -AutoSize
        }
    }
    catch {
        # For any other errors (e.g. access denied), display the error in red
        $errMsg = $_.Exception.Message
        Write-LogHost ("Error retrieving events for ID {0}: {1}" -f $eventId, $errMsg) -Color Red
    }
    Write-Host ""
}
