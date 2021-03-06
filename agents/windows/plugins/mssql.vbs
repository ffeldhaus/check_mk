' -----------------------------------------------------------------------------
' Check_MK windows agent plugin to gather information from local MSSQL servers
'
' This plugin can be used to collect information of all running MSSQL server
' on the local system.
'
' The current implementation of the check uses the "trusted authentication"
' where no user/password needs to be created in the MSSQL server instance by
' default. It is only needed to grant the user as which the Check_MK windows
' agent service is running access to the MSSQL database.
'
' Another option is to create a mssql.ini file in MK_CONFDIR and write the
' credentials of a database user to it which shal be used for monitoring:
'
' [auth]
' type = db
' username = monitoring
' password = secret-pw
'
' The following sources are asked:
' 1. Registry - To gather a list of local MSSQL-Server instances
' 2. WMI - To check for the state of the MSSQL service
' 2. MSSQL-Servers via ADO/sqloledb connection to gather infos these infos:
'      a) list and sizes of available databases
'      b) counters of the database instance
'
' This check has been developed with MSSQL Server 2008 R2. It should work with
' older versions starting from at least MSSQL Server 2005.
' -----------------------------------------------------------------------------

Option Explicit

Dim WMI, FSO, SHO, items, objItem, prop, instVersion, registry
Dim sources, instances, instance, instance_id, instance_name
Dim cfg_dir, cfg_file, hostname

Const HKLM = &H80000002

' Directory of all database instance names
Set instances = CreateObject("Scripting.Dictionary")
Set FSO = CreateObject("Scripting.FileSystemObject")
Set SHO = CreateObject("WScript.Shell")

hostname = SHO.ExpandEnvironmentStrings("%COMPUTERNAME%")
cfg_dir = SHO.ExpandEnvironmentStrings("%MK_CONFDIR%")

Sub addOutput(text)
    wscript.echo text
End Sub

Function readIniFile(path)
    Dim parsed : Set parsed = CreateObject("Scripting.Dictionary")
    If path <> "" Then
        Dim FH
        Set FH = FSO.OpenTextFile(path)
        Dim line, sec, pair
        Do Until FH.AtEndOfStream
            line = Trim(FH.ReadLine())
            If Left(line, 1) = "[" Then
                sec = Mid(line, 2, Len(line) - 2)
                Set parsed(sec) = CreateObject("Scripting.Dictionary")
            Else
                If line <> "" Then
                    pair = Split(line, "=")
                    If 1 = UBound(pair) Then
                        parsed(sec)(Trim(pair(0))) = Trim(pair(1))
                    End If
                End If
            End If
            Set FH = Nothing
        Loop
        FH.Close
    End If
    Set readIniFile = parsed
    Set parsed = Nothing
End Function

Set registry = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")
Set sources = CreateObject("Scripting.Dictionary")

Dim service, i, version, edition, value_types, value_names, value_raw, cluster_name
Set WMI = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")

'
' Gather instances on this host, store instance in instances and output version section for it
'
registry.EnumValues HKLM, "SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL", _
                          value_names, value_types

If Not IsArray(value_names) Then
    addOutput("ERROR: Failed to gather SQL server instances")
    wscript.quit(1)
End If

For i = LBound(value_names) To UBound(value_names)
    instance_id = value_names(i)

    registry.GetStringValue HKLM, "SOFTWARE\Microsoft\Microsoft SQL Server\" & _
                                  "Instance Names\SQL", _
                                  instance_id, instance_name

    ' HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQLServer\CurrentVersion
    registry.GetStringValue HKLM, "SOFTWARE\Microsoft\Microsoft SQL Server\" & _
                                  instance_name & "\MSSQLServer\CurrentVersion", _
                                  "CurrentVersion", version

    ' HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\Setup
    registry.GetStringValue HKLM, "SOFTWARE\Microsoft\Microsoft SQL Server\" & _
                                  instance_name & "\Setup", _
                                  "Edition", edition

    ' Check whether or not this instance is clustered
    registry.GetStringValue HKLM, "SOFTWARE\Microsoft\Microsoft SQL Server\" & _
                                  instance_name & "\Cluster", "ClusterName", cluster_name

    If IsNull(cluster_name) Then
        cluster_name = ""

        ' In case of instance name "MSSQLSERVER" always use (local) as connect string
        If instance_id = "MSSQLSERVER" Then
            sources.add instance_id, "(local)"
        Else
            sources.add instance_id, hostname & "\" & instance_id
        End If
    Else
        ' In case the instance name is "MSSQLSERVER" always use the virtual server name
        If instance_id = "MSSQLSERVER" Then
            sources.add instance_id, cluster_name
        Else
            sources.add instance_id, cluster_name & "\" & instance_id
        End If
    End If

    addOutput("<<<mssql_versions:sep(124)>>>")
    addOutput("MSSQL_" & instance_id & "|" & version & "|" & edition & "|" & cluster_name)

    ' Only collect results for currently running instances
    Set service = WMI.ExecQuery("SELECT State FROM Win32_Service " & _
                          "WHERE Name = 'MSSQL$" & instance_id & "' AND State = 'Running'")
    If Not IsNull(service) Then
        instances.add instance_id, ""
    End If
Next

Set service  = Nothing
Set WMI      = Nothing
Set registry = Nothing


Dim CONN, RS, CFG, AUTH

' Initialize database connection objects
Set CONN      = CreateObject("ADODB.Connection")
Set RS        = CreateObject("ADODB.Recordset")
CONN.Provider = "sqloledb"

' Loop all found server instances and connect to them
' In my tests only the connect using the "named instance" string worked
For Each instance_id In instances.Keys
    ' Use either an instance specific config file named mssql_<instance-id>.ini
    ' or the default mysql.ini file.
    cfg_file = cfg_dir & "\mssql_" & instance & ".ini"
    If Not FSO.FileExists(cfg_file) Then
        cfg_file = cfg_dir & "\mssql.ini"
        If Not FSO.FileExists(cfg_file) Then
            cfg_file = ""
        End If
    End If

    Set CFG = readIniFile(cfg_file)
    If Not CFG.Exists("auth") Then
        Set AUTH = CreateObject("Scripting.Dictionary")
    Else
        Set AUTH = CFG("auth")
    End If

    ' At this place one could implement to use other authentication mechanism
    If Not AUTH.Exists("type") or AUTH("type") = "system" Then
        CONN.Properties("Integrated Security").Value = "SSPI"
    Else
        CONN.Properties("User ID").Value = AUTH("username")
        CONN.Properties("Password").Value = AUTH("password")
    End If

    CONN.Properties("Data Source").Value = sources(instance_id)
    CONN.Open

    ' Get counter data for the whole instance
    addOutput( "<<<mssql_counters>>>" )
    RS.Open "SELECT GETUTCDATE() as utc_date", CONN
    addOutput( "None utc_time None " & RS("utc_date") )
    RS.Close

    RS.Open "SELECT counter_name, object_name, instance_name, cntr_value " & _
            "FROM sys.dm_os_performance_counters " & _
            "WHERE object_name NOT LIKE '%Deprecated%'", CONN

    Dim objectName, counterName, instanceName, value
    Do While NOT RS.Eof
        objectName   = Replace(Replace(Trim(RS("object_name")), " ", "_"), "$", "_")
        counterName  = LCase(Replace(Trim(RS("counter_name")), " ", "_"))
        instanceName = Replace(Trim(RS("instance_name")), " ", "_")
        If instanceName = "" Then
            instanceName = "None"
        End If
        value        = Trim(RS("cntr_value"))
        addOutput( objectName & " " & counterName & " " & instanceName & " " & value )
        RS.MoveNext
    Loop
    RS.Close

    RS.Open "SELECT session_id, wait_duration_ms, wait_type, blocking_session_id " & _
            "FROM sys.dm_os_waiting_tasks " & _
            "WHERE blocking_session_id <> 0 ", CONN
    addOutput( "<<<mssql_blocked_sessions>>>" )
    Dim session_id, wait_duration_ms, wait_type, blocking_session_id
    Do While NOT RS.Eof
        session_id = Trim(RS("session_id"))
        wait_duration_ms = Trim(RS("wait_duration_ms"))
        wait_type = Trim(RS("wait_type"))
        blocking_session_id = Trim(RS("blocking_session_id"))
        addOutput(session_id & " " & wait_duration_ms & " " & wait_type & " " & blocking_session_id)
        RS.MoveNext
    Loop
    RS.Close

    ' First only read all databases in this instance and save it to the db names dict
    RS.Open "EXEC sp_databases", CONN
    Dim x, dbName, dbNames
    Set dbNames = CreateObject("Scripting.Dictionary")
    Do While NOT RS.Eof
        dbName = RS("DATABASE_NAME")
        dbNames.add dbName, ""
       RS.MoveNext
    Loop
    RS.Close

    ' Now gather the db size and unallocated space
    addOutput( "<<<mssql_tablespaces>>>" )
    Dim dbSize, unallocated, reserved, data, indexSize, unused
    For Each dbName in dbNames.Keys
        ' Switch to other database and then ask for stats
        RS.Open "USE [" & dbName & "]", CONN
        ' sp_spaceused is a stored procedure which returns two selects
        ' which need to be looped
        RS.Open "EXEC sp_spaceused", CONN
        i = 0
        Do Until RS Is Nothing
            Do While NOT RS.Eof
                'For Each x in RS.fields
                '    wscript.echo x.name & " " & x.value
                'Next
                If i = 0 Then
                    ' Size of the current database in megabytes. database_size includes both data and log files.
                    dbSize      = Trim(RS("database_size"))
                    ' Space in the database that has not been reserved for database objects.
                    unallocated = Trim(RS("unallocated space"))
                Elseif i = 1 Then
                    ' Total amount of space allocated by objects in the database.
                    reserved    = Trim(RS("reserved"))
                    ' Total amount of space used by data.
                    data        = Trim(RS("data"))
                    ' Total amount of space used by indexes.
                    indexSize   = Trim(RS("index_size"))
                    ' Total amount of space reserved for objects in the database, but not yet used.
                    unused      = Trim(RS("unused"))
                End If
                RS.MoveNext
            Loop
            Set RS = RS.NextRecordset
            i = i + 1
        Loop
        addOutput("MSSQL_" & instance_id & " " & Replace(dbName, " ", "_") & " " & dbSize & " " & _
                  unallocated & " " & reserved & " " & data & " " & indexSize & " " & unused)
        Set RS = CreateObject("ADODB.Recordset")
    Next

    ' Loop all databases to get the date of the last backup. Only show databases
    ' which have at least one backup
    Dim lastBackupDate
    addOutput( "<<<mssql_backup>>>" )
    For Each dbName in dbNames.Keys
        RS.open "SELECT CONVERT(VARCHAR, DATEADD(s, DATEDIFF(s, '19700101', MAX(backup_finish_date)), '19700101'), 120) AS last_backup_date " & _
                "FROM msdb.dbo.backupset " & _
                "WHERE database_name = '" & dbName & "'", CONN
        Do While Not RS.Eof
            lastBackupDate = Trim(RS("last_backup_date"))
            If lastBackupDate <> "" Then
                addOutput("MSSQL_" & instance_id & " " & Replace(dbName, " ", "_") & _
                          " " & lastBackupDate)
            End If
            RS.MoveNext
        Loop
        RS.Close
    Next

    'Loop all databases to get the size of the transaction log
    addOutput( "<<<mssql_transactionlogs>>>" )

    For Each dbName in dbNames.Keys
       RS.Open "USE [" & dbName & "];", CONN
       RS.Open "SELECT name, physical_name," &_
                  "  cast(max_size/128 as bigint) as MaxSize," &_
                  "  cast(size/128 as bigint) as AllocatedSize," &_
                  "  cast(FILEPROPERTY (name, 'spaceused')/128 as bigint) as UsedSize," &_
                  "  case when max_size = '-1' then '1' else '0' end as Unlimited" &_
                  " FROM sys.database_files WHERE type_desc = 'LOG'", CONN
        Do While Not RS.Eof
            addOutput( instance_id & " " & Replace(dbName, " ", "_") & " " & Replace(RS("name"), " ", "_") & _
                      " " & Replace(RS("physical_name"), " ", "_") & " " & _
                      RS("MaxSize") & " " & RS("AllocatedSize") & " " & RS("UsedSize")) & _
                      " " & RS("Unlimited")
            RS.MoveNext
        Loop
        RS.Close
    Next

    'Loop all databases to get the size of the transaction log
    addOutput( "<<<mssql_datafiles>>>" )
    For Each dbName in dbNames.Keys
        RS.Open "USE [" & dbName & "];", CONN
        RS.Open "SELECT name, physical_name," &_
                "  cast(max_size/128 as bigint) as MaxSize," &_
                "  cast(size/128 as bigint) as AllocatedSize," &_
                "  cast(FILEPROPERTY (name, 'spaceused')/128 as bigint) as UsedSize," &_
                "  case when max_size = '-1' then '1' else '0' end as Unlimited" &_
                " FROM sys.database_files WHERE type_desc = 'ROWS'", CONN
        Do While Not RS.Eof
            addOutput( instance_id & " " & Replace(dbName, " ", "_") & " " & Replace(RS("name"), " ", "_") & _
                      " " & Replace(RS("physical_name"), " ", "_") & " " & _
                      RS("MaxSize") & " " & RS("AllocatedSize") & " " & RS("UsedSize")) & _
                      " " & RS("Unlimited")
            RS.MoveNext
        Loop
        RS.Close
    Next
    
    addOutput("<<<mssql_clusters>>>")
    Dim active_node, nodes
    For Each dbName in dbNames.Keys
        RS.Open "USE [" & dbName & "];", CONN
    
        ' Skip non cluster instances
        RS.Open "SELECT SERVERPROPERTY('IsClustered') AS is_clustered", CONN
        If RS("is_clustered") = 0 Then
            RS.Close
            Continue
        End If
        RS.Close
        
        nodes = ""
        RS.Open "SELECT nodename FROM sys.dm_os_cluster_nodes", CONN
        Do While Not RS.Eof
            If nodes <> "" Then
                nodes = nodes & ","
            End If    
            nodes = nodes & RS("nodename")
            RS.MoveNext
        Loop
        RS.Close

        active_node = "-"
        RS.Open "SELECT SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS active_node", CONN
        Do While Not RS.Eof
            active_node = RS("active_node")
            RS.MoveNext
        Loop
        RS.Close
        
        addOutput(instance_id & " " & Replace(dbName, " ", "_") & " " & active_node & " " & nodes)
    Next

    CONN.Close
Next

Set sources = nothing
Set instances = nothing
Set RS = nothing
Set CONN = nothing
Set FSO = nothing
Set SHO = nothing
