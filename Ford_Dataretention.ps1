[CmdletBinding()]
Param(

    [Parameter(Mandatory = $False)]
    [String]
    $cxDB = "localhost\\SQLExpress",

    [Parameter(Mandatory = $False)]
    [String]
    $dbUser = "",

    [Parameter(Mandatory = $False)]
    [String]
    $dbPass = "",

    [Parameter(Mandatory = $False)]
    [String]
    $cxHost,

    [Parameter(Mandatory = $False)]
    [String]
    $cxUser,

    [Parameter(Mandatory = $False)]
    [String]
    $cxPass,

    [Parameter(Mandatory = $False)]
    [int]
    $runLimitHours,

    [Parameter(Mandatory=$False)]
    [switch]
    $exec,

    [Parameter(Mandatory=$False)]
    [switch]
    $v
)

# -----------------------------------------------------------------
# This custom data retention script depends
# on the Invoke-SqlCmd2 module
#
# If the module is not already installed,
# execute the following in a Powershell window:
#      Install-Module -Name Invoke-SqlCmd2
# -----------------------------------------------------------------
Import-Module "Invoke-SqlCmd2" -DisableNameChecking

# CxSAST REST API auth values
[String] $CX_REST_GRANT_TYPE = "password"
[String] $CX_REST_SCOPE = "sast_rest_api"
[String] $CX_REST_CLIENT_ID = "resource_owner_client"
# Constant shared secret between this client and the Checkmarx server.
[String] $CX_REST_CLIENT_SECRET = "014DF517-39D1-4453-B7B3-9930C563627C"


# -----------------------------------------------------------------
# Reads config from JSON file
# -----------------------------------------------------------------
Class Config {

    hidden $config
    hidden [IO] $io
    [String] $configFile

    # Constructs and loads configuration from given path
    Config ([String] $configFile) {
        $this.io = [IO]::new()
        $this.configFile = $configFile
        $this.LoadConfig()
    }

    # Loads configuration from configured path
    LoadConfig () {
        try {
            $cp = $this.configFile
            $configFilePath = (Get-Item -Path $cp).FullName
            $this.io.Log("Loading config from $configFilePath")
            $this.config = Get-Content -Path $configFilePath -Raw | ConvertFrom-Json
        }
        catch {
            $this.io.Log("Provided configuration file at [" + $this.configconfigFile + "] is missing / corrupt.")
            exit -1
        }
    }

    [PsCustomObject] GetConfig() {
        return $this.config
    }
}

# -----------------------------------------------------------------
# DateTime Utility
# -----------------------------------------------------------------
Class DateTimeUtil {

    # Gets timestamp in UTC in configured format
    [String] NowUTCFormatted() {
        return $this.Format($this.NowUTC())
    }

    # Gets timestamp in UTC
    [DateTime] NowUTC() {
        return (Get-Date).ToUniversalTime()
    }

    # Converts to UTC and formats
    [String] ToUTCAndFormat([DateTime] $dateTime) {
        return $this.Format($dateTime.ToUniversalTime())
    }

    # Formats time based on configured format
    [String] Format([DateTime] $dateTime) {
        return $dateTime.ToString($script:config.log.timeFormat)
    }

}

# -----------------------------------------------------------------
# Input/Output Utility
# -----------------------------------------------------------------
Class IO {

    # General logging
    static [String] $LOG_FILE = "cx_data_retention.log"
    hidden [DateTimeUtil] $dateUtil = [DateTimeUtil]::new()

    # Logs given message to configured log file
    Log ([String] $message) {
        # Write to log file
        $this.WriteToFile($message, [IO]::LOG_FILE)
        # Also write to console
        $this.Console($message)
    }

    # Write given string to host console
    Console ([String] $message) {
        Write-Host $this.AddTimestamp($message)
    }

    # Write a pretty header output
    WriteHeader() {
        $this.Log("------------------------------------------------------------------------")
        $this.Log("Checkmarx Data Retention (based on locking scans that meet criteria)")
        $this.Log("Checkmarx Manager: $($script:config.cx.host)")
        $this.Log("Checkmarx Database: $($script:config.cx.db.instance)")
        if ($($script:config.cx.db.username)) {
            $this.Log("Database Auth: Using SQLServer Authentication.")
            $this.Log("Please ensure SQLServer Account [$($script:config.cx.db.username)] has sufficient privileges to access data.")
        }
        else {
            $this.Log("Database Auth: Using SQLServer Integrated (Windows) Authentication")
        }
        $this.Log("== Data Retention Parameters ==")
        $this.Log("Days To Retain (Going Back From Today): $($script:config.dataRetention.daysToRetain)")
        $this.Log("Number Of Latest Scans To Retain: $($script:config.dataRetention.latestScansToRetain)")
        $this.Log("Number Of Earliest Scans To Retain: $($script:config.dataRetention.earliestScansToRetain)")
        $this.Log("Remove Scans With No Code Changes?: $($script:config.dataRetention.removeScansWithNoCodeChange)")
        $this.Log("Data Retention Runtime Limit (Hours): $($script:config.dataRetention.durationLimitHours)")
        $this.Log("------------------------------------------------------------------------")
    }

    # Utility that writes to given file
    hidden WriteToFile([String] $message, [String] $file) {
        Add-content $file -Value $this.AddTimestamp($message)
    }

    hidden [String] AddTimestamp ([String] $message) {
        return $this.dateUtil.NowUTCFormatted() + ": " + $message
    }
}

# -----------------------------------------------------------------
# Credentials Utility
# -----------------------------------------------------------------
Class CredentialsUtil {

    # Returns a PSCredential object from given plaintext username/password
    [PSCredential] GetPSCredential ([String] $username, [String] $plainTextPassword) {
        [SecureString] $secPassword = ConvertTo-SecureString $plainTextPassword -AsPlainText -Force
        return New-Object System.Management.Automation.PSCredential ($username, $secPassword)
    }
}

# -----------------------------------------------------------------
# Database Client
# -----------------------------------------------------------------
Class DBClient {

    hidden [IO] $io = [IO]::new()
    hidden [PSCredential] $sqlAuthCreds
    hidden [String] $serverInstance

    # Constructs a DBClient based on given server and creds
    DBClient ([String] $serverInstance, [String]$dbUser, [String] $dbPass) {
        $this.serverInstance = $serverInstance
        if ($dbUser -and $dbPass) {
            $this.sqlAuthCreds = [CredentialsUtil]::new().GetPSCredential($dbUser, $dbPass)
        }
    }

    # Executes given SQL using either SQLServer authentication or Windows, depending on given PSCredential object
    [PSObject] ExecSQL ([String] $sql, [PSCustomObject] $parameters) {
        # $this.io.Console("Executing $sql")
        try {
            if ($this.sqlAuthCreds.UserName) {
                $cred = $this.sqlAuthCreds
                return Invoke-Sqlcmd2 -ServerInstance $this.serverInstance -Credential @cred -Query $sql -SqlParameters $parameters
            }
            else {
                return Invoke-Sqlcmd2 -ServerInstance $this.serverInstance -Query $sql -SqlParameters $parameters
            }
        }
        catch {
            $this.io.Log("Database execution error. $($_.Exception.GetType().FullName), $($_.Exception.Message)")
            # Force exit during dev run - runtime savior
            Exit
        }
    }

}

# -----------------------------------------------------------------
# Scan Lock Implementation
# -----------------------------------------------------------------
Class ScanLockService {

    hidden [IO] $io
    hidden [DateTime] $lastRun
    hidden [DBClient] $dbClient
    hidden [DateTimeUtil] $dateUtil
    hidden [PSCustomObject] $drConfig

    # Constructs an ScanLockService
    ScanLockService ([DBClient] $dbClient, [PSCustomObject] $drConfig) {
        $this.io = [IO]::new()
        $this.dateUtil = [DateTimeUtil]::new()
        $this.lastRun = Get-Date
        $this.dbClient = $dbClient
        $this.drConfig = $drConfig
    }

    # Lock scans
    [bool] LockScans() {

        if ($script:v) {
          $this.io.Log("Fetching scans from DB...")
        }

        [String] $totalScansSQL = "SELECT COUNT(*) AS nScans FROM cxdb.dbo.taskScans"
        [PSObject] $totalScansResult = $this.dbClient.ExecSQL($totalScansSQL, @{})
        [int] $nTotalScans = 0
        if ($totalScansResult) {
          $nTotalScans = [int] $totalScansResult["nScans"]
        }
        if ($script:v) {
          $this.io.Log("Total scan records found in the database: [$nTotalScans]")
        }

        # drConfig
        [Hashtable] $lockScanParams = @{ }
        # Note the negative daysToRetain, resulting in subtraction
        # where this parameter is used.
        $lockScanParams.Add("lookbackInDays", - $($this.drConfig.daysToRetain))
        $lockScanParams.Add("earliestScansToRetain", $this.drConfig.earliestScansToRetain)
        $lockScanParams.Add("latestScansToRetain", $this.drConfig.latestScansToRetain)
        if ($this.drConfig.removeScansWithNoCodeChange -eq $true) {
            $lockScanParams.Add("commentPattern", "%Attempt to perform scan % - No code changes were detected;%")
        }

        # Scans that should be Locked
        # Earliest X scans (configuration 'earliestScansToRetain')
        # Latest Y scans (Configuration 'latestScansToRetain')
        [String] $lockScansSQL =
        "SELECT earliest.ScanDate AS ScanDate, earliest.ScanId AS ScanId, earliest.ProjectName, earliest.ProjectId FROM
          	(SELECT
          	    ts.id AS ScanId,
          	    ts.StartTime AS ScanDate,
          	    p.Name AS ProjectName,
          	    p.id AS ProjectId,
          	    ROW_NUMBER() OVER (PARTITION BY ts.projectId ORDER BY ts.startTime ASC) AS scan_no
          	FROM
          	    cxdb.dbo.taskScans ts JOIN cxdb.dbo.projects p ON ts.ProjectId = p.Id
            WHERE ts.is_deprecated = 0
          	) AS earliest
         WHERE earliest.scan_no <=@earliestScansToRetain
         UNION
         SELECT latest.ScanDate, latest.ScanId AS ScanId, latest.ProjectName, latest.ProjectId FROM
          	(SELECT
          	    ts.id AS ScanId,
           	    ts.StartTime AS ScanDate,
          	    p.Name AS ProjectName,
          	    p.id AS ProjectId,
          	    ROW_NUMBER() OVER (PARTITION BY ts.projectId ORDER BY ts.startTime DESC) AS scan_no
          	FROM
          		cxdb.dbo.taskScans ts JOIN cxdb.dbo.projects p ON ts.ProjectId = p.Id
            WHERE ts.is_deprecated = 0
          	) AS latest
         WHERE latest.scan_no <=@latestScansToRetain
         UNION
         SELECT ts.StartTime AS ScanDate, ts.id AS ScanId, p.Name AS ProjectName, p.id AS ProjectId
            FROM cxdb.dbo.taskScans ts JOIN cxdb.dbo.projects p ON ts.ProjectId = p.Id
            WHERE ts.startTime >= DATEADD(DAY, @lookbackInDays, GETDATE()) AND ts.is_deprecated = 0"

        if ($this.drConfig.removeScansWithNoCodeChange) {
            $lockScansSQL += "
            AND
            (
               ts.comment NOT LIKE @commentPattern
            )"
        }

        if ($script:v) {
          $this.io.Log("Looking for scans that meet retaining criteria.")
          $this.io.Log("CRITERIA: Keep scans from last [$($this.drConfig.daysToRetain)] day(s).")
          $this.io.Log("CRITERIA: Keep earliest [$($this.drConfig.earliestScansToRetain)], and latest [$($this.drConfig.latestScansToRetain)] scans.")
          if ($this.drConfig.removeScansWithNoCodeChange) {
              $this.io.Log("CRITERIA: Remove scans that reported no code changes.")
          }
        }
        [PSObject] $scanIds = $this.dbClient.ExecSQL($lockScansSQL, $lockScanParams)

        [System.Collections.ArrayList] $scansToLock = @()

        if ($scanIds) {

            if ($script:v) {
              $this.io.Log("Found [$($scanIds.Count)] scans that match retaining criteria.")
            }

            foreach ($result in $scanIds) {

                $scanId = [int]$result["ScanId"]
                $scansToLock.Add($scanId)

                if ($script:v) {
                  $projectId = $result["ProjectId"]
                  $projectName = $result["ProjectName"]
                  $scanDate = $result["ScanDate"]
                  $this.io.Log("Will retain scan [ProjectId: $projectId, Project: $projectName, ScanDate: $scanDate, ScanId: $scanId]")
                }
            }

            # Lock only scans that meet filter criteria
            if ($script:v) {
              $this.io.Log("Locking total [$($scansToLock.Count)] scans.")
            }
            $scanIds = $scansToLock -join ","
            if ($script:exec) {
                [String] $lockScansSQL = "UPDATE cxdb.dbo.taskScans SET IsLocked=1 WHERE id in ($scanIds)"
                $this.dbClient.ExecSQL($lockScansSQL, @{})
            }

            [int] $nScansToRemove = $nTotalScans-$scansToLock.Count
            $this.io.Log("Will remove [$nScansToRemove] scans.")

            return $true
        }
        else {
            if ($script:v) {
              $this.io.Log("No scans matched retention criteria.")
            }
            return $false
        }
    }
}


# -----------------------------------------------------------------
# REST request body
# -----------------------------------------------------------------
Class RESTBody {

    [String] $grantType
    [String] $scope
    [String] $clientId
    [String] $clientSecret

    RESTBody(
        [String] $grantType,
        [String] $scope,
        [String] $clientId,
        [String] $clientSecret
    ) {
        $this.grantType = $grantType
        $this.scope = $scope
        $this.clientId = $clientId
        $this.clientSecret = $clientSecret
    }
}



# -----------------------------------------------------------------
# REST Client
# -----------------------------------------------------------------
Class RESTClient {

    [String] $baseUrl
    [RESTBody] $restBody

    hidden [String] $token
    hidden [IO] $io = [IO]::new()

    # Constructs a RESTClient based on given base URL and body
    RESTClient ([String] $cxHost, [RESTBody] $restBody) {
        $this.baseUrl = $cxHost + "/cxrestapi"
        $this.restBody = $restBody
    }

    <#
    # Logins to the CxSAST REST API
    # and returns an API token
    #>
    [bool] login ([String] $username, [String] $password) {
        [bool] $isLoginSuccessful = $False
        $body = @{
            username      = $username
            password      = $password
            grant_type    = $this.restBody.grantType
            scope         = $this.restBody.scope
            client_id     = $this.restBody.clientId
            client_secret = $this.restBody.clientSecret
        }

        [psobject] $response = $null
        try {
            $loginUrl = $this.baseUrl + "/auth/identity/connect/token"
            if ($script:v) {
              $this.io.Log("Logging into Checkmarx CxSAST...")
            }
            $response = Invoke-RestMethod -uri $loginUrl -method POST -body $body -contenttype 'application/x-www-form-urlencoded'
        }
        catch {
            if ($script:v) {
              $this.io.Log("$_")
            }
            $this.io.Log("Could not authenticate against Checkmarx REST API. Reason: HTTP [$($_.Exception.Response.StatusCode.value__)] - $($_.Exception.Response.StatusDescription).")
        }

        if ($response -and $response.access_token) {
            $isLoginSuccessful = $True
            # Track token internally
            $this.token = $response.token_type + " " + $response.access_token
        }


        return $isLoginSuccessful
    }

    <#
    # Invokes a given REST API
    #>
    [Object] invokeAPI ([String] $requestUri, [String] $method, [Object] $body, [int] $apiResponseTimeoutSeconds) {

        # Sanity : If not logged in, do not proceed
        if ( ! $this.token) {
            throw "Must execute login() first, prior to other API calls."
        }

        $headers = @{
            "Authorization" = $this.token
            "Accept"        = "application/json;v=1.0"
        }

        $response = $null

        try {
            $uri = $this.baseUrl + $requestUri
            if ($method -ieq "GET") {
                $response = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -TimeoutSec $apiResponseTimeoutSeconds
            }
            else {
                $response = Invoke-RestMethod -Uri $uri -Method $method.ToString() -Headers $headers -Body $body -TimeoutSec $apiResponseTimeoutSeconds
            }
        }
        catch {
            $this.io.Log("REST API call failed : [$($_.exception.Message)]")
            $this.io.Log("Status Code: $($_.exception.Response.StatusCode)")
            if ($script:v) {
              $this.io.Log("$_")
            }
        }

        return $response
    }
}



# -----------------------------------------------------------------
# Data Retention Execution
# -----------------------------------------------------------------
Class DataRetention {

    hidden [IO] $io
    hidden [PSObject] $config
    hidden [int] $numOfScansToKeep = 0
    hidden [RESTClient] $cxSastRestClient

    DataRetention([PSObject] $config) {
        $this.io = [IO]::new()
        $this.config = $config
    }

    # Executes data retention
    Execute() {

        # Create a RESTBody specific to CxSAST REST API calls
        $cxSastRestBody = [RESTBody]::new($script:CX_REST_GRANT_TYPE, $script:CX_REST_SCOPE, $script:CX_REST_CLIENT_ID, $script:CX_REST_CLIENT_SECRET)
        # Create a REST Client for CxSAST REST API
        $this.cxSastRestClient = [RESTClient]::new($this.config.cx.host, $cxSastRestBody)
        # Login to the CxSAST server
        [bool] $isLoginOk = $this.cxSastRestClient.login($this.config.cx.username, $this.config.cx.password)

        if ($isLoginOk -eq $True) {
          if ($script:v) {
            $this.io.Log("Login was successful.")
          }
          $this.StartDataRetention($this.config.dataRetention.durationLimitHours)
        }

    }

    # Call data retention start
    [Object] StartDataRetention ([int] $dataRetentionDurationLimitHrs) {
        $this.io.Log("Running data retention...")

        $dataRetentionParams = @{
          NumOfSuccessfulScansToPreserve = 0
          durationLimitInHours = $dataRetentionDurationLimitHrs
        }
        [String] $apiUrl = "/sast/dataRetention/byNumberOfScans"
        [PSObject] $resp = $null
        if ($script:exec) {
            $resp = $this.cxSastRestClient.invokeAPI($apiUrl, 'POST', $dataRetentionParams, 0)
        }
        else {
          $this.io.Log("Dry-run. No scans removed.")
        }
        return $resp
    }

}


# ========================================== #
# ============ Execution Entry ============= #
# ========================================== #

[PSCustomObject] $config = [Config]::new(".\ford-cx_data_retention_config.json").GetConfig()

# Override config from command line params, if provided
if ($dbUser) { $config.cx.db.username = $dbUser }
if ($dbPass) { $config.cx.db.password = $dbPass }
if ($cxUser) { $config.cx.username = $cxUser }
if ($cxPass) { $config.cx.password = $cxPass }
if ($cxHost) { $config.cx.host = $cxHost }
if ($runLimitHours) { $config.dataRetention.durationLimitHours = $runLimitHours }

[IO] $io = [IO]::new()
$io.WriteHeader()

if (!$exec) {
    $io.Log("")
    $io.Log("===========================================================================")
    $io.Log("========== THIS IS A DRY RUN (default). No changes will be made. ==========")
    $io.Log("==========                                                       ==========")
    $io.Log("========== To execute data retention, use -exec parameter.       ==========")
    if (!$v) {
      $io.Log("==========       -v for verbose output.                          ==========")
    }
    $io.Log("===========================================================================")
    $io.Log("")
}

[DBClient] $dbClient = [DBClient]::new($config.cx.db.instance, $config.cx.db.username, $config.cx.db.password)
[ScanLockService] $scanLockService = [ScanLockService]::new($dbClient, $config.dataRetention)
[DataRetention] $dataRetention = [DataRetention]::new($config)

[bool] $runDR = $scanLockService.LockScans()
if ($runDR) {
  $dataRetention.Execute()
}

$io.Log("Done.")
