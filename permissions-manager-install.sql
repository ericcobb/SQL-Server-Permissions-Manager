/**************************************************************************
	PERMISSIONS MANAGER
	Author: Eric Cobb - http://www.sqlnuggets.com/
	Supported Versions: SQL Server 2008 R2, SQL Server 2012, SQL Server 2014, and SQL Server 2016
	License:
			MIT License
			
			Copyright (c) 2017 Eric Cobb

			Permission is hereby granted, free of charge, to any person obtaining a copy
			of this software and associated documentation files (the "Software"), to deal
			in the Software without restriction, including without limitation the rights
			to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
			copies of the Software, and to permit persons to whom the Software is
			furnished to do so, subject to the following conditions:

			The above copyright notice and this permission notice shall be included in all
			copies or substantial portions of the Software.

			THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
			IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
			FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
			AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
			LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
			OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
			SOFTWARE.
***************************************************************************/

--Change this to whatever database you want to create the Permissions Manager objects in.
USE [Master]
GO

IF NOT EXISTS (SELECT * FROM sys.schemas WHERE [name] = N'perms' ) 
    EXEC sp_executesql N'CREATE SCHEMA [perms] AUTHORIZATION [dbo];';
GO

/**************************************************************************
	Create Tables
***************************************************************************/


IF OBJECT_ID('perms.Snapshots') IS NULL
BEGIN
	CREATE TABLE [perms].[Snapshots](
		[ID] [bigint] IDENTITY(1,1) NOT NULL CONSTRAINT [PK_Perms_Snapshots] PRIMARY KEY CLUSTERED ,
		[DatabaseName] [nvarchar](128) NOT NULL,
		[CaptureDate] [datetime] NOT NULL CONSTRAINT [DF_Perms_Snapshots_CaptureDate]  DEFAULT (getdate())
	);
END
GO


IF OBJECT_ID('perms.DatabasePermissions') IS NULL
BEGIN
	CREATE TABLE [perms].[DatabasePermissions](
		[ID] [bigint] IDENTITY(1,1) NOT NULL CONSTRAINT [PK_Perms_DatabasePermissions] PRIMARY KEY CLUSTERED,
		[SnapshotID] [bigint] NOT NULL,
		[State] [char](1) NOT NULL,
		[StateDesc] [nvarchar](60) NOT NULL,
		[PermissionName] [nvarchar](128) NOT NULL,
		[UserName] [nvarchar](256) NOT NULL
	);

	ALTER TABLE [perms].[DatabasePermissions]  WITH CHECK ADD CONSTRAINT [FK_Perms_DatabasePermissions_Snapshot] FOREIGN KEY([SnapshotID]) REFERENCES [perms].[Snapshots] ([ID]);
END
GO


IF OBJECT_ID('perms.ObjectPermissions') IS NULL
BEGIN
	CREATE TABLE [perms].[ObjectPermissions](
		[ID] [bigint] IDENTITY(1,1) NOT NULL CONSTRAINT [PK_Perms_Object_Permissions] PRIMARY KEY CLUSTERED ,
		[SnapshotID] [bigint] NOT NULL,
		[State] [char](1) NOT NULL,
		[StateDesc] [nvarchar](60) NOT NULL,
		[PermissionName] [nvarchar](128) NOT NULL,
		[SchemaName] [nvarchar](128) NOT NULL,
		[ObjectName] [nvarchar](128) NOT NULL,
		[UserName] [nvarchar](256) NOT NULL,
		[ClassDesc] [nvarchar](60) NOT NULL,
		[ColumnName] [nvarchar](128) NULL
	);

	ALTER TABLE [perms].[ObjectPermissions]  WITH CHECK ADD CONSTRAINT [FK_Perms_ObjectPermissions_Snapshot] FOREIGN KEY([SnapshotID]) REFERENCES [perms].[Snapshots] ([ID]);
END
GO


IF OBJECT_ID('perms.RoleMemberships') IS NULL
BEGIN
	CREATE TABLE [perms].[RoleMemberships](
		[ID] [bigint] IDENTITY(1,1) NOT NULL CONSTRAINT [PK_Perms_Role_Memberships] PRIMARY KEY CLUSTERED ,
		[SnapshotID] [bigint] NOT NULL,
		[RoleName] [nvarchar](256) NOT NULL,
		[UserName] [nvarchar](256) NOT NULL
	);

	ALTER TABLE [perms].[RoleMemberships]  WITH CHECK ADD CONSTRAINT [FK_Perms_RoleMemberships_Snapshot] FOREIGN KEY([SnapshotID]) REFERENCES [perms].[Snapshots] ([ID]);
END
GO


IF OBJECT_ID('perms.Roles') IS NULL
BEGIN
	CREATE TABLE [perms].[Roles](
		[ID] [bigint] IDENTITY(1,1) NOT NULL CONSTRAINT [PK_Perms_Roles] PRIMARY KEY CLUSTERED ,
		[SnapshotID] [bigint] NOT NULL,
		[RoleName] [nvarchar](128) NOT NULL,
		[RoleType] [char](1) NOT NULL,
		[RoleTypeDesc] [nvarchar](60) NOT NULL,
		[DefaultSchema] [nvarchar](128) NULL
	);

	ALTER TABLE [perms].[Roles]  WITH CHECK ADD  CONSTRAINT [FK_Perms_Roles_Snapshot] FOREIGN KEY([SnapshotID]) REFERENCES [perms].[Snapshots] ([ID]);
END
GO


IF OBJECT_ID('perms.SchemaPermissions') IS NULL
BEGIN
	CREATE TABLE [perms].[SchemaPermissions](
		[ID] [bigint] IDENTITY(1,1) NOT NULL CONSTRAINT [PK_Perms_Schema_Permissions] PRIMARY KEY CLUSTERED ,
		[SnapshotID] [bigint] NOT NULL,
		[State] [char](1) NOT NULL,
		[StateDesc] [nvarchar](60) NOT NULL,
		[PermissionName] [nvarchar](128) NOT NULL,
		[SchemaName] [nvarchar](128) NOT NULL,
		[UserName] [nvarchar](256) NOT NULL
	);

	ALTER TABLE [perms].[SchemaPermissions]  WITH CHECK ADD  CONSTRAINT [FK_Perms_SchemaPermissions_Snapshot] FOREIGN KEY([SnapshotID]) REFERENCES [perms].[Snapshots] ([ID]);
END
GO


IF OBJECT_ID('perms.Users') IS NULL
BEGIN
	CREATE TABLE [perms].[Users](
		[ID] [bigint] IDENTITY(1,1) NOT NULL CONSTRAINT [PK_Perms_Users] PRIMARY KEY CLUSTERED ,
		[SnapshotID] [bigint] NOT NULL,
		[UserName] [nvarchar](256) NOT NULL,
		[UserType] [char](1) NOT NULL,
		[UserTypeDesc] [nvarchar](60) NOT NULL,
		[DefaultSchema] [nvarchar](128) NULL,
		[LoginName] [nvarchar](128) NOT NULL,
		[LoginType] [char](1) NOT NULL,
		[isDisabled] [bit] NOT NULL,
		[SID] [varbinary](85) NULL,
		[PasswordHash] [varbinary](256) NULL
	);
	
	ALTER TABLE [perms].[Users]  WITH CHECK ADD  CONSTRAINT [FK_Perms_Users_Snapshot] FOREIGN KEY([SnapshotID]) REFERENCES [perms].[Snapshots] ([ID]);
END
GO


/**************************************************************************
	Create Stored Procedures
***************************************************************************/


--If our procedure doesn't already exist, create one with a dummy query to be overwritten.
IF OBJECT_ID('perms.createSnapshot') IS NULL
  EXEC sp_executesql N'CREATE PROCEDURE perms.createSnapshot AS	SELECT 1;';
GO

ALTER PROCEDURE [perms].[createSnapshot]
(
	@DBName	NVARCHAR(128)
)
AS

/**************************************************************************
	Author: Eric Cobb - http://www.sqlnuggets.com/
		License:
			MIT License
			Copyright (c) 2017 Eric Cobb
			View full license disclosure: https://github.com/ericcobb/SQL-Server-Metrics-Pack/blob/master/LICENSE
			
	Purpose: 
			This stored procedure is used to create a snapshot of the current permissions in a given database

	Parameters:
			@DBName - REQUIRED - Name of the Database you want to create a Permissions Snapshot for.

	Usage:	
			--Take a Permissions Snapshot for the MyDB database
			EXEC [dbo].[createSnapshot] @DBName='MyDB';
***************************************************************************/

BEGIN
	SET NOCOUNT ON;
	
	DECLARE @SnapshotID BIGINT;
	DECLARE @CRLF NCHAR(2) = NCHAR(13)+NCHAR(10);

	INSERT INTO [perms].[Snapshots] (DatabaseName) VALUES (@DBName);
	SELECT @SnapshotID = SCOPE_IDENTITY();

	DECLARE @SQLStmt NVARCHAR(MAX);
	SELECT @SQLStmt = N'USE ' + QUOTENAME(@DBName) +';
	' + @CRLF

	/* 
		##-Users-##
	*/
	CREATE TABLE #Users(
		[UserName] [nvarchar](128) NOT NULL,
		[UserType] [char](1) NOT NULL,
		[UserTypeDesc] [nvarchar](60) NOT NULL,
		[DefaultSchema] [nvarchar](128) NULL,
		[LoginName] [nvarchar](128) NOT NULL,
		[LoginType] [char](1) NOT NULL,
		[isDisabled] [bit] NOT NULL,
		[SID] [varbinary](85) NULL,
		[PasswordHash] [varbinary](256) NULL
	);

	SELECT @SQLStmt = @SQLStmt + N'
	INSERT INTO #Users([UserName], [UserType], [UserTypeDesc], [DefaultSchema], [LoginName], [LoginType], [isDisabled], [SID], [PasswordHash])
	SELECT dp.name
		,dp.type
		,dp.type_desc
		,dp.default_schema_name
		,sp.name
		,sp.type
		,sp.is_disabled
		,sp.sid
		,l.password_hash
	FROM sys.database_principals dp
	JOIN sys.server_principals sp on dp.sid = sp.sid
	LEFT JOIN sys.sql_logins l on l.principal_id = sp.principal_id 
	WHERE dp.type_desc IN (''WINDOWS_GROUP'',''WINDOWS_USER'',''SQL_USER'')
	AND dp.name NOT IN (''dbo'',''guest'',''INFORMATION_SCHEMA'',''sys'');
	' + @CRLF

	/* 
		##-Roles-##
	*/
	CREATE TABLE #Roles(
		[RoleName] [nvarchar](128) NOT NULL,
		[RoleType] [char](1) NOT NULL,
		[RoleTypeDesc] [nvarchar](60) NOT NULL,
		[DefaultSchema] [nvarchar](128) NULL
	);

	SELECT @SQLStmt = @SQLStmt + N'
	INSERT INTO #Roles ([RoleName], [RoleType], [RoleTypeDesc], [DefaultSchema])
	SELECT name
		,type
		,type_desc
		,default_schema_name
	FROM sys.database_principals
	WHERE type_desc IN (''DATABASE_ROLE'',''APPLICATION_ROLE'')
	AND is_fixed_role = 0
	AND principal_id <> 0;
	' + @CRLF


	/* 
		##-Role Memberships-##
	*/
	CREATE TABLE #RoleMemberships(
		[RoleName] [nvarchar](256) NOT NULL,
		[UserName] [nvarchar](256) NOT NULL
	);
	SELECT @SQLStmt = @SQLStmt + N'
	INSERT INTO #RoleMemberships([RoleName], [UserName])
	SELECT USER_NAME(role_principal_id)
		,USER_NAME(member_principal_id)
	FROM sys.database_role_members;
	' + @CRLF


	/* 
		##-Object permissions - GRANT, DENY, REVOKE statements-##
	*/
	CREATE TABLE #ObjectPermissions(
		[State] [char](1) NOT NULL,
		[StateDesc] [nvarchar](60) NOT NULL,
		[PermissionName] [nvarchar](128) NOT NULL,
		[SchemaName] [nvarchar](128) NOT NULL,
		[ObjectName] [nvarchar](128) NOT NULL,
		[UserName] [nvarchar](256) NOT NULL,
		[ClassDesc] [nvarchar](60) NOT NULL,
		[ColumnName] [nvarchar](128) NULL
	);
	SELECT @SQLStmt = @SQLStmt + N'
	INSERT INTO #ObjectPermissions ([State], [StateDesc], [PermissionName], [SchemaName], [ObjectName], [UserName], [ClassDesc], [ColumnName])
	SELECT perm.state -- D (DENY), R (REVOKE), G (GRANT), W (GRANT_WITH_GRANT_OPTION)
		,perm.state_desc -- actual state command for D, R, G, W
		,perm.permission_name
		,SCHEMA_NAME(obj.schema_id)
		,obj.name
		,USER_NAME(perm.grantee_principal_id)
		,perm.class_desc
		,cl.name
	FROM sys.database_permissions AS perm
	INNER JOIN sys.objects AS obj ON perm.major_id = obj.[object_id]
	LEFT JOIN sys.columns AS cl ON cl.column_id = perm.minor_id AND cl.[object_id] = perm.major_id
	WHERE perm.class_desc = ''OBJECT_OR_COLUMN'';
	' + @CRLF


	/* 
		##-Schema assignments - GRANT, DENY, REVOKE statements-##
	*/

	CREATE TABLE #SchemaPermissions(
		[State] [char](1) NOT NULL,
		[StateDesc] [nvarchar](60) NOT NULL,
		[PermissionName] [nvarchar](128) NOT NULL,
		[SchemaName] [nvarchar](128) NOT NULL,
		[UserName] [nvarchar](256) NOT NULL
	);
	SELECT @SQLStmt = @SQLStmt + N'
	INSERT INTO #SchemaPermissions ([State], [StateDesc], [PermissionName], [SchemaName], [UserName])
	SELECT perm.state
		,perm.state_desc
		,perm.permission_name
		,SCHEMA_NAME(major_id)
		,USER_NAME(grantee_principal_id)
	FROM sys.database_permissions perm
	WHERE class_desc = ''SCHEMA'';
	' + @CRLF


	/* 
		##-Database permissions - GRANT, DENY, REVOKE-##
	*/

	CREATE TABLE #DatabasePermissions(
		[State] [char](1) NOT NULL,
		[StateDesc] [nvarchar](60) NOT NULL,
		[PermissionName] [nvarchar](128) NOT NULL,
		[UserName] [nvarchar](256) NOT NULL
	);

	SELECT @SQLStmt = @SQLStmt + N'
	INSERT INTO #DatabasePermissions ([State], [StateDesc], [PermissionName], [UserName])
	SELECT perm.state -- D (DENY), R (REVOKE), G (GRANT), W (GRANT_WITH_GRANT_OPTION)
		,perm.state_desc -- actual state command for D, R, G; GRANT_WITH_GRANT_OPTION for W
		,perm.permission_name
		,USER_NAME(perm.grantee_principal_id)
	FROM sys.database_permissions AS perm
	WHERE class_desc = ''DATABASE'';
	' + @CRLF

	--PRINT @SQLStmt
	EXECUTE sp_executesql @SQLStmt

	
	/* 
		##-Load Database permissions into real tables-##
	*/

	INSERT INTO [perms].[Users]([SnapshotID], [UserName], [UserType], [UserTypeDesc], [DefaultSchema], [LoginName], [LoginType], [isDisabled], [SID], [PasswordHash])
	SELECT @SnapshotID, [UserName], [UserType], [UserTypeDesc], [DefaultSchema], [LoginName], [LoginType], [isDisabled], [SID], [PasswordHash] FROM #Users;

	INSERT INTO [perms].[Roles] ([SnapshotID], [RoleName], [RoleType], [RoleTypeDesc], [DefaultSchema])
	SELECT @SnapshotID, [RoleName], [RoleType], [RoleTypeDesc], [DefaultSchema] FROM #Roles;

	INSERT INTO [perms].[RoleMemberships]([SnapshotID], [RoleName], [UserName])
	SELECT @SnapshotID, [RoleName], [UserName] FROM #RoleMemberships;

	INSERT INTO [perms].[ObjectPermissions] ([SnapshotID], [State], [StateDesc], [PermissionName], [SchemaName], [ObjectName], [UserName], [ClassDesc], [ColumnName])
	SELECT @SnapshotID, [State], [StateDesc], [PermissionName], [SchemaName], [ObjectName], [UserName], [ClassDesc], [ColumnName] FROM #ObjectPermissions;

	INSERT INTO [perms].[SchemaPermissions] ([SnapshotID], [State], [StateDesc], [PermissionName], [SchemaName], [UserName])
	SELECT @SnapshotID, [State], [StateDesc], [PermissionName], [SchemaName], [UserName] FROM #SchemaPermissions;

	INSERT INTO [perms].[DatabasePermissions] ([SnapshotID], [State], [StateDesc], [PermissionName], [UserName])
	SELECT @SnapshotID, [State], [StateDesc], [PermissionName], [UserName] FROM #DatabasePermissions;

	DROP TABLE #Users;
	DROP TABLE #Roles;
	DROP TABLE #RoleMemberships;
	DROP TABLE #ObjectPermissions;
	DROP TABLE #SchemaPermissions;
	DROP TABLE #DatabasePermissions;

END
GO


--If our procedure doesn't already exist, create one with a dummy query to be overwritten.
IF OBJECT_ID('perms.snapshotAllDBs') IS NULL
  EXEC sp_executesql N'CREATE PROCEDURE perms.snapshotAllDBs AS	SELECT 1;';
GO

ALTER PROCEDURE [perms].[snapshotAllDBs]
AS

/**************************************************************************
	Author: Eric Cobb - http://www.sqlnuggets.com/
		License:
			MIT License
			Copyright (c) 2017 Eric Cobb
			View full license disclosure: https://github.com/ericcobb/SQL-Server-Metrics-Pack/blob/master/LICENSE
			
	Purpose: 
			This stored procedure is used to create a snapshot of the current permissions in all databases on a server.

	Parameters:
			NONE

	Usage:	
			--Take a Permissions Snapshot for all databases.
			EXEC [dbo].[snapshotAllDBs];
***************************************************************************/

BEGIN
	SET NOCOUNT ON;

	DECLARE @tmpDatabases TABLE (
				ID INT IDENTITY PRIMARY KEY
				,DatabaseName NVARCHAR(128)
				,Completed BIT
			);

	DECLARE @CurrentID INT;
	DECLARE @CurrentDatabaseName NVARCHAR(128);

	INSERT INTO @tmpDatabases (DatabaseName, Completed)
	SELECT [Name], 0
	FROM sys.databases
	WHERE state = 0
	AND source_database_id IS NULL
	ORDER BY [Name] ASC


	WHILE EXISTS (SELECT * FROM @tmpDatabases WHERE Completed = 0)
	BEGIN
		SELECT TOP 1 @CurrentID = ID,
					 @CurrentDatabaseName = DatabaseName
		FROM @tmpDatabases
		WHERE Completed = 0
		ORDER BY ID ASC

		EXEC [perms].[createSnapshot] @DBName = @CurrentDatabaseName

		-- Update that the database is completed
		UPDATE @tmpDatabases
		SET Completed = 1
		WHERE ID = @CurrentID

		-- Clear variables
		SET @CurrentID = NULL
		SET @CurrentDatabaseName = NULL
	END
END
GO


--If our procedure doesn't already exist, create one with a dummy query to be overwritten.
IF OBJECT_ID('perms.applyPermissions') IS NULL
  EXEC sp_executesql N'CREATE PROCEDURE perms.applyPermissions AS SELECT 1;';
GO

ALTER PROCEDURE [perms].[applyPermissions]
	@DBName NVARCHAR(128),
	@SnapshotID INT = NULL,
	@User NVARCHAR(256) = NULL,
	@CreateLogins BIT = 1,
	@ExecuteScript BIT = 0,	
	@CopySID BIT = 1, --Copies the SID of a SQL user
	@DestinationDatabase  NVARCHAR(128) = NULL,
	@AltUserNames XML = NULL
AS

/**************************************************************************
	Author: Eric Cobb - http://www.sqlnuggets.com/
		License:
			MIT License
			Copyright (c) 2017 Eric Cobb
			View full license disclosure: https://github.com/ericcobb/SQL-Server-Metrics-Pack/blob/master/LICENSE
			
	Purpose: 
			This stored procedure is used to apply a Permissions Snapshot to a specified database; 
			If a Snapshot ID is specified, it will restore that Snapshot, 
			otherwise it defaults to the most recent Snapshot for the specified database;

	Parameters:
			@DBName - REQUIRED - Name of the Database you want to apply a Permissions Snapshot to.
			@SnapshotID - OPTIONAL - ID of the specific Snapshot you want to apply.
			@User - OPTIONAL - User Name of a specific user you want permissions applied for.
			@CreateLogins - OPTIONAL - Flag for whether or not to generate the CREATE LOGIN scripts for the user(s) listed in the Permissions Snapshot.
			@ExecuteScript - OPTIONAL -	Flag for whether or not to actually apply the Permissions Snapshot.
										If 1: Automatically apply the permissions to the databse.
										If 0: Generates the permissions script to be reviewed/run manually.
			@CopySID - OPTIONAL - Generates the SID of a SQL user as part of the script
			@DestinationDatabase - OPTIONAL - Database to apply Permissions Snapshot to; defaults to the specified @DBName.
			@AltUserNames - OPTIONAL - Used for cloning a specified user's permissions to a new user. (see [perms].[clonePermissions] procedure)
				VALUE FOR @AltUserNames = 
				<altusers>
					<user>
						<original>OriginalUser</original>	-- REQUIRED. original UserName, as found in the perms.Users table
						<new>NewUser</new>			-- REQUIRED. new UserName. should include domain name if appropriate - e.g. HCA\ibm8561
						<DefaultSchema>dbo</DefaultSchema>	-- OPTIONAL. default schema
						<LoginName></LoginName>		-- OPTIONAL. login name. Defaults to new UserName
						<LoginType></LoginType>	-- OPTIONAL, defaults to U. S = SQL User, U = Windows User, G = Windows Group
					</user>
				</altusers>

	Usage:	
			--Apply the most recent Permissions Snapshot to the MyDB database.
			EXEC [dbo].[applyPermissions] @DBName='MyDB';

***************************************************************************/

BEGIN
	SET NOCOUNT ON;

	DECLARE @SQLSTMT NVARCHAR(4000);
	DECLARE @SQLSTMT2 NVARCHAR(4000);
	DECLARE @VSnapshotID INT = NULL;

	DECLARE @CRLF NCHAR(2) = NCHAR(13) + NCHAR(10);

	-- Create Temp Table
	CREATE TABLE #SQLResults
	(
		ID		INT IDENTITY(1,1) NOT NULL,
		STMT	NVARCHAR(1000)	NOT NULL
	)

	-- Determine Correct Snapshot ID
	IF @SnapshotID IS NULL
		SELECT TOP 1 @VSnapshotID = [ID] FROM [perms].[Snapshots] WHERE [DatabaseName] = @DBName ORDER BY [CaptureDate] DESC;
	ELSE
		SELECT TOP 1 @VSnapshotID = [ID] FROM [perms].[Snapshots] WHERE [DatabaseName] = @DBName AND [ID] = @SnapshotID; --ORDER BY [CaptureDate] DESC

	IF @VSnapshotID IS NULL -- STILL???
	BEGIN
		RAISERROR(N'No Valid Snapshot Available',16,1);
		RETURN;
	END

	IF @DestinationDatabase IS NULL
		SET @DestinationDatabase = @DBName;

	-- Setup Alternate UserNames Capability
	CREATE TABLE #AltUsers (
		OriginalUser NVARCHAR(256) NOT NULL,
		NewUser NVARCHAR(256) NOT NULL,
		DefaultSchema NVARCHAR(128) NULL,
		LoginName NVARCHAR(128) NULL,
		LoginType CHAR(1) NULL DEFAULT 'U'
	);

	IF @AltUserNames IS NOT NULL
	BEGIN
		INSERT INTO #AltUsers (OriginalUser, NewUser, DefaultSchema, LoginName, LoginType)
		SELECT Tbl.Col.value('original[1]', 'sysname'),
			Tbl.Col.value('new[1]','sysname'),
			Tbl.Col.value('DefaultSchema[1]','sysname'),
			Tbl.Col.value('LoginName[1]','sysname'),
			Tbl.Col.value('LoginType[1]','char(1)')
		FROM @AltUserNames.nodes('/altusers/user') Tbl(Col);
	END;

	INSERT INTO #AltUsers (OriginalUser, NewUser, DefaultSchema, LoginName, LoginType)
	SELECT UserName, UserName, DefaultSchema, LoginName, LoginType
	FROM perms.Users
	WHERE UserName NOT IN (SELECT OriginalUser FROM #AltUsers)
		AND SnapshotID = @VSnapshotID

	UPDATE #AltUsers
	SET #AltUsers.DefaultSchema = u.DefaultSchema
	FROM #AltUsers
	JOIN perms.Users u ON #AltUsers.OriginalUser = u.UserName
	WHERE #AltUsers.DefaultSchema IS NULL

	UPDATE #AltUsers
	SET LoginName = NewUser
	WHERE LoginName IS NULL

	UPDATE #AltUsers
	SET LoginType = 'U'
	WHERE LoginType IS Null

	INSERT INTO #SQLResults (STMT)
	SELECT '-- Database: ' + @DBName
	INSERT INTO #SQLResults (STMT)
	SELECT '-- Snapshot ID: ' + CAST(@VsnapshotID AS varchar(10))

	INSERT INTO #SQLResults(STMT) VALUES ('')

	INSERT INTO #SQLResults(STMT) VALUES ('USE ' + @DestinationDatabase + ';')

	INSERT INTO #SQLResults(STMT) VALUES ('')


	-- ### LOGINS ###
	INSERT INTO #SQLResults(STMT) VALUES ('-- ### LOGINS ###')

	-- U, S, G
	IF @CreateLogins = 1
	BEGIN
		INSERT INTO #SQLResults (STMT)
		SELECT 'IF NOT EXISTS (SELECT * FROM sys.server_principals WHERE name = N''' + u.LoginName + ''') '
			+ 'BEGIN '
			+ 'CREATE LOGIN ' + QUOTENAME(u.LoginName)
			+ CASE
				WHEN u.LoginType = 'U' THEN ' FROM WINDOWS '
				WHEN u.LoginType = 'G' THEN ' FROM WINDOWS '
				ELSE ' WITH PASSWORD = ' + CONVERT(VARCHAR(MAX), p.[PasswordHash], 1) + ' HASHED'
			  END
			+ CASE 
				WHEN @CopySID = 1 AND u.LoginType = 'S' THEN ', SID=' + CONVERT(varchar(max), p.SID, 1)-- ALTER LOGIN ' + QUOTENAME(LoginName) + ' DISABLE '
				ELSE ''
			  END
			+ ' END'
		FROM #AltUsers u
		INNER JOIN [perms].[Users] p ON p.LoginName = u.OriginalUser
		WHERE (@User IS NULL OR u.OriginalUser = @User)
		AND p.SnapshotID = @VSnapshotID;

		INSERT INTO #SQLResults (STMT)
		SELECT 'ALTER LOGIN ' + QUOTENAME(LoginName) + ' DISABLE'
		FROM [perms].[Users] u
		WHERE u.SnapshotID = @VSnapshotID
			AND (u.isDisabled = 1)
			AND (@User IS NULL OR u.UserName = @User);

	END;

	INSERT INTO #SQLResults(STMT) VALUES ('')

	-- ### REPAIR EXISTING USERS ###
	INSERT INTO #SQLResults(STMT) VALUES ('-- ### REPAIR USERS ###')

	INSERT INTO #SQLResults (STMT)
	SELECT 'IF EXISTS (SELECT * FROM sys.database_principals dp '
		+ 'LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid '
		+ 'WHERE dp.type = ''S'' '
		+ 'AND sp.sid IS NULL '
		+ 'AND dp.name = N' + QUOTENAME(NewUser,'''') + ') '
		+ 'EXEC sp_change_users_login ''Auto_Fix'', ' + QUOTENAME(NewUser,'''') + ';'
	FROM #AltUsers u
	WHERE (@User IS NULL OR u.OriginalUser = @User)
		AND u.LoginType = 'S';

	INSERT INTO #SQLResults(STMT) VALUES ('')

	-- ### USERS ###
	INSERT INTO #SQLResults(STMT) VALUES ('-- ### USERS ###')

	INSERT INTO #SQLResults (STMT)
	SELECT 'IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = N' + QUOTENAME(NewUser,'''') + ') '
		+ 'CREATE USER ' + QUOTENAME(NewUser) + ' FOR LOGIN ' + QUOTENAME(LoginName)
		+ CASE
			WHEN DefaultSchema IS NOT NULL THEN	' WITH DEFAULT_SCHEMA=' + QUOTENAME(DefaultSchema)
			ELSE ''
		  END
		+ ';'
	FROM #AltUsers u
	WHERE (@User IS NULL OR u.OriginalUser = @User);

	INSERT INTO #SQLResults(STMT) VALUES ('')

	-- ### ROLES ###
	/* First things first, we need to put the roles into #AltUsers so that when
	we do the actual permissions, they are there */
	INSERT INTO #AltUsers (OriginalUser, NewUser)
	SELECT RoleName, RoleName
	FROM perms.Roles
	WHERE SnapshotID = @VSnapshotID

	-- First, do Database Roles
	INSERT INTO #SQLResults(STMT) VALUES ('-- ### ROLES ###')
	INSERT INTO #SQLResults (STMT)
	SELECT 'IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = N' + QUOTENAME(RoleName,'''') + ' AND type = ''R'') '
		+ 'CREATE ROLE ' + QUOTENAME(RoleName) + ' AUTHORIZATION [dbo]'
	FROM [perms].[Roles] r
	WHERE r.SnapshotID = @VSnapshotID
		AND r.RoleType = 'R'
		AND (@User IS NULL OR r.RoleName = @User);

	-- Then, do Application Roles.  Note, doesn't transfer password
	INSERT INTO #SQLResults (STMT)
	SELECT 'IF NOT EXISTS (SELECT * FROM sys.database_principals WHERE name = N''' + QUOTENAME(RoleName) + ''' AND type = ''A'') '
		+ 'CREATE APPLICATION ROLE ' + QUOTENAME(RoleName) + ' WITH PASSWORD = ''Healthtrust123'' '
		+ CASE 
			WHEN DefaultSchema IS NOT NULL THEN	', DEFAULT_SCHEMA=' + QUOTENAME(DefaultSchema)
			ELSE ''
		  END
	FROM [perms].[Roles] r
	WHERE r.SnapshotID = @VSnapshotID
		AND r.RoleType = 'A'
		AND (@User IS NULL);


	INSERT INTO #SQLResults(STMT) VALUES ('')

	-- ### ROLE ASSIGNMENTS ###
	INSERT INTO #SQLResults(STMT) VALUES ('-- ### ROLE ASSIGNMENTS ###')
	INSERT INTO #SQLResults (STMT)
	SELECT 'IF IS_ROLEMEMBER(' + QUOTENAME(RoleName,'''') + ',' + QUOTENAME(au.NewUser,'''') + ') = 0 '
		+ 'EXEC sp_addrolemember @RoleName = ' + QUOTENAME(RoleName,'''') + ', @membername = ' + QUOTENAME(au.NewUser,'''')
	FROM [perms].[RoleMemberships] rm
	JOIN #AltUsers au ON rm.UserName = au.OriginalUser
	WHERE rm.SnapshotID = @VSnapshotID
		AND (@User IS NULL OR rm.UserName = @User);

	INSERT INTO #SQLResults(STMT) VALUES ('')


	-- ### OBJECT PERMISSIONS ###
	INSERT INTO #SQLResults(STMT) VALUES ('-- ### OBJECT PERMISSIONS ###')
	INSERT INTO #SQLResults (STMT)
	SELECT 'IF NOT EXISTS (SELECT * FROM sys.database_permissions '
		+ 'WHERE class_desc = ''OBJECT_OR_COLUMN'' '
		+ 'AND grantee_principal_id = DATABASE_PRINCIPAL_ID(' + QUOTENAME(au.NewUser,'''') + ') '
		+ 'AND Permission_Name = ' + QUOTENAME(PermissionName,'''')
		+ ' AND State_Desc = ' + QUOTENAME(StateDesc,'''')
		+ ' AND major_id = OBJECT_ID(N' + QUOTENAME(ObjectName,'''') + ') '
		+ CASE
			WHEN ColumNname IS NULL THEN SPACE(0)
			ELSE 'AND minor_id = columnproperty(object_id(N''' + SchemaName + '.' + ObjectName + '''),N''' + ColumNname + ''', ''columnid'') '
		  END
		+ ') '
		+ CASE
			WHEN [State]<> 'W' THEN StateDesc + SPACE(1)
			ELSE 'GRANT '
		  END
		+ PermissionName 
		+ ' ON ' + QUOTENAME(SchemaName) + '.' + QUOTENAME(ObjectName)
		+  CASE
			WHEN ColumNname IS NULL THEN SPACE(1)
			ELSE ' (' + QUOTENAME(ColumNname) + ')'
		   END
		+ 'TO ' + QUOTENAME(au.NewUser)
		+ CASE
			WHEN [State]<> 'W' THEN SPACE(0)
			ELSE ' WITH GRANT OPTION'
		  END
	FROM [perms].[ObjectPermissions] op
		JOIN #AltUsers au ON op.UserName = au.OriginalUser
	WHERE op.SnapshotID = @VSnapshotID
		AND (@User IS NULL OR op.UserName = @User);

	INSERT INTO #SQLResults(STMT) VALUES ('')

	-- ### SCHEMA PERMISSIONS ###
	INSERT INTO #SQLResults(STMT) VALUES ('-- ### SCHEMA PERMISSIONS ###')
	INSERT INTO #SQLResults (STMT)
	SELECT 'IF NOT EXISTS (SELECT * FROM sys.database_permissions '
		+ 'WHERE class_desc = ''SCHEMA'' '
		+ 'AND grantee_principal_id = DATABASE_PRINCIPAL_ID(' + QUOTENAME(au.NewUser,'''') + ') '
		+ 'AND Permission_Name = ' + QUOTENAME(PermissionName,'''')
		+ ' AND State_Desc = ' + QUOTENAME(StateDesc,'''')
		+ ' AND major_id = SCHEMA_ID(N' + QUOTENAME(SchemaName,'''') + ')) '
		+ CASE
			WHEN [State]<> 'W' THEN StateDesc + SPACE(1)
			ELSE 'GRANT '
		  END
		+ PermissionName 
		+ ' ON SCHEMA :: ' + SchemaName
		+ ' TO ' + QUOTENAME(au.NewUser)
		+ CASE
			WHEN [State]<> 'W' THEN ';'
			ELSE ' WITH GRANT OPTION;'
		  END
	FROM [perms].[SchemaPermissions] sp
		JOIN #AltUsers au ON sp.UserName = au.OriginalUser
	WHERE sp.SnapshotID = @VSnapshotID
		AND (@User IS NULL OR sp.UserName = @User);

	INSERT INTO #SQLResults(STMT) VALUES ('')

	-- ### DATABASE PERMISSIONS ###
	INSERT INTO #SQLResults(STMT) VALUES ('-- ### DATABASE PERMISSIONS ###')
	INSERT INTO #SQLResults (STMT)
	SELECT 'IF NOT EXISTS (SELECT * FROM sys.database_permissions '
		+ 'WHERE class_desc = ''DATABASE'' '
		+ 'AND grantee_principal_id = DATABASE_PRINCIPAL_ID(' + QUOTENAME(au.NewUser,'''') + ') '
		+ 'AND Permission_Name = ' + QUOTENAME(PermissionName,'''')
		+ ' AND State_Desc = ' + QUOTENAME(StateDesc,'''')
		+ ' AND major_id = 0) '
		+ CASE
			WHEN [State]<> 'W' THEN StateDesc + SPACE(1)
			ELSE 'GRANT '
		  END
		+ PermissionName 
		+ ' TO ' + QUOTENAME(au.NewUser)
		+ CASE
			WHEN [State]<> 'W' THEN ';'
			ELSE ' WITH GRANT OPTION;'
		  END
	FROM [perms].[DatabasePermissions] dp
		JOIN #AltUsers au ON dp.UserName = au.OriginalUser
	WHERE dp.SnapshotID = @VSnapshotID
		AND (@User IS NULL OR dp.UserName = @User);

	--If @executeScript = 0, return the statements.
	IF @ExecuteScript = 0
	BEGIN
		SELECT 
			CAST((STUFF
			(
				(
					SELECT @CRLF + STMT
					FROM #SQLResults
					ORDER BY ID
					FOR XML PATH(''), TYPE
				).value('.[1]','NVARCHAR(MAX)'), 1, 2, '')
			) AS XML) AS sqlSTMT

	END
	ELSE
	BEGIN
		DECLARE @sqlSTMT_prep NVARCHAR(4000)
		DECLARE sql_cursor CURSOR LOCAL FAST_FORWARD FOR
		SELECT STMT FROM #SQLResults 
		WHERE STMT <> '' AND STMT NOT LIKE 'USE %' AND STMT NOT LIKE '--%'
		ORDER BY ID
	
		OPEN sql_cursor
		FETCH NEXT FROM sql_cursor INTO @sqlSTMT
	
		WHILE @@FETCH_STATUS = 0
		BEGIN
			SELECT @sqlSTMT_prep = 'USE ' + @DestinationDatabase + '; ';
			SELECT @sqlSTMT_prep = @sqlSTMT_prep + @sqlSTMT;
			exec sp_ExecuteSQL @sqlSTMT_prep;
			--SELECT @sqlSTMT_prep;
		
			FETCH NEXT FROM sql_cursor INTO @sqlSTMT
		END
	
		CLOSE sql_cursor
		DEALLOCATE sql_cursor
	END

	DROP TABLE #SQLResults;
	DROP TABLE #AltUsers;

END

GO


--If our procedure doesn't already exist, create one with a dummy query to be overwritten.
IF OBJECT_ID('perms.clonePermissions') IS NULL
  EXEC sp_executesql N'CREATE PROCEDURE perms.clonePermissions AS SELECT 1;';
GO

ALTER PROCEDURE [perms].[clonePermissions]
	@UserName NVARCHAR(256)
	,@NewUser NVARCHAR(256)
	,@logintype CHAR(1) = 'U'
	,@CopySID BIT = 0
	,@CreateLogins BIT = 1
	,@ExecuteScript BIT = 0
		
AS 

/**************************************************************************
	Author: Eric Cobb - http://www.sqlnuggets.com/
		License:
			MIT License
			Copyright (c) 2017 Eric Cobb
			View full license disclosure: https://github.com/ericcobb/SQL-Server-Metrics-Pack/blob/master/LICENSE
			
	Purpose: 
			This stored procedure is used to copy all of the permissions from a given user and assign those permissions to another user.
			It will do this for every database on a server, so if a user has permissions on 3 databases, the new user and permissions will be added to those 3 databases.

	Parameters:
			@UserName - REQUIRED - the user we want to clone
			@NewUser - REQUIRED - the user name of the new user we want to create
			@logintype - OPTIONAL - defaults to U. S = SQL User, U = Windows User, G = Windows Group	
			@CopySID - OPTIONAL - Copies the SID of a SQL user
			@CreateLogins - OPTIONAL - Flag for whether or not to generate the CREATE LOGIN scripts for the user(s) listed in the Permissions Snapshot.
			@ExecuteScript - OPTIONAL -	Flag for whether or not to actually apply the Permissions Snapshot.
										If 1: Automatically apply the permissions to the databse.
										If 0 (Default): Generates the permissions script to be reviewed/run manually.

	Usage:	
			--Generate a script to create User2 with all of the permissions that User1 has, but do not automatically run the generated script;
			EXEC [perms].[clonePermissions] @UserName = 'user1', @NewUser = 'user2', @CreateLogins = 1, @ExecuteScript = 0

***************************************************************************/

BEGIN
	SET NOCOUNT ON;

	DECLARE @sql NVARCHAR(4000)
			,@db NVARCHAR(128)
	-- List the DBs this user has access to, based on the most recent Snapshots
	SELECT DISTINCT
			[ID] = s1.ID,
			[DB] = databasename,
			[CaptureDate]
	INTO    #CurrentSnaps
	FROM    perms.Snapshots s1
			INNER JOIN perms.RoleMemberships rm ON rm.SnapshotID = s1.ID
			INNER JOIN sys.databases db ON db.name = s1.databasename and state_desc = 'ONLINE'--only return active, online databases
	WHERE   rm.username = @UserName
			AND CaptureDate IN ( SELECT    MAX(CaptureDate)
							  FROM      perms.Snapshots s2
							  WHERE     s2.databasename = s1.databasename )
	ORDER BY [DB];

	--SELECT * FROM #CurrentSnaps

	--IF there are databases found, we need to add the new user to them
	IF (SELECT COUNT(*) FROM #CurrentSnaps) > 0
	BEGIN
		--Create an XML string to pass to the permissions proc; this tells it what user we want to clone the new user as.
		DECLARE @AltUsernames XML = '<altusers><user><original>'+@UserName+'</original><new>'+@NewUser+'</new><logintype>'+@logintype+'</logintype></user></altusers>'

		--In case our user has permission on more than 1 database, we're going to loop through the list to make sure we get them all.
		DECLARE cur CURSOR LOCAL FAST_FORWARD FOR SELECT DB FROM #CurrentSnaps
		OPEN cur

		FETCH NEXT FROM cur INTO @db

		WHILE @@FETCH_STATUS = 0 
		BEGIN
			-- 1) Write our SQL string that calls the PROC that actually applies the permissions.
			SET @SQL = '
			EXEC [perms].[applyPermissions]
				@DBName = ['+@db+'],
				@User = ['+@UserName+'],
				@CreateLogins = '+CAST(@CreateLogins AS CHAR(1))+',
				@ExecuteScript = '+CAST(@ExecuteScript AS CHAR(1))+',
				@CopySID = '+CAST(@CopySID AS CHAR(1))+',
				@AltUsernames = '''+CAST(@AltUsernames AS NVARCHAR(500))+'''
			'
			--make sure the DB is there, we've had cases where dabases got snapshotted, but were later deleted. 
			IF DB_ID(@db) IS NOT NULL
			BEGIN
				-- 2) now run the command to call the PROC listed above
				EXEC sp_executesql @SQL	
			END

			FETCH NEXT FROM cur INTO @db
		END
		CLOSE cur    
		DEALLOCATE cur

	END

	DROP TABLE #CurrentSnaps

END

GO


--If our procedure doesn't already exist, create one with a dummy query to be overwritten.
IF OBJECT_ID('perms.purgeSnapshots') IS NULL
  EXEC sp_executesql N'CREATE PROCEDURE perms.purgeSnapshots AS SELECT 1;';
GO

ALTER PROCEDURE [perms].[purgeSnapshots]
	@DaysToKeep INT = 90
AS

/**************************************************************************
	Author: Eric Cobb - http://www.sqlnuggets.com/
		License:
			MIT License
			Copyright (c) 2017 Eric Cobb
			View full license disclosure: https://github.com/ericcobb/SQL-Server-Metrics-Pack/blob/master/LICENSE
			
	Purpose: 
			This stored procedure is used to purge old Permission Snapshots from the database

	Parameters:
			@DaysToKeep - REQUIRED - How many days worth of data do you want to keep?  Anything older than this number (defualts to 90 days) will be deleted. 

	Usage:	
			--Delete all snapshots older than 90 days (default);
			EXEC [perms].[purgeSnapshots];

			--Delete all snapshots older than 120 days;
			EXEC [perms].[purgeSnapshots] @DaysToKeep = 120;

***************************************************************************/

BEGIN
	SET NOCOUNT ON;

	BEGIN TRANSACTION

		BEGIN TRY

		DECLARE @snapshots TABLE ([SnapshotID] INT PRIMARY KEY CLUSTERED NOT NULL);
		
		--create a list of the snapshots to delete
		INSERT INTO @snapshots ([SnapshotID])
		SELECT ID FROM [perms].[Snapshots] ss
		WHERE ss.[CaptureDate] < DATEADD(day,0-@DaysToKeep,GETDATE())

		--go forth and delete
		DELETE p
		FROM [perms].[DatabasePermissions] p
		INNER JOIN @snapshots s ON s.[SnapshotID] = p.[SnapshotID];

		DELETE p
		FROM [perms].[SchemaPermissions] p
		INNER JOIN @snapshots s ON s.[SnapshotID] = p.[SnapshotID];
		
		DELETE p
		FROM [perms].[ObjectPermissions] p
		INNER JOIN @snapshots s ON s.[SnapshotID] = p.[SnapshotID];
		
		DELETE p
		FROM [perms].[RoleMemberships] p
		INNER JOIN @snapshots s ON s.[SnapshotID] = p.[SnapshotID];
		
		DELETE p
		FROM [perms].[Roles] p
		INNER JOIN @snapshots s ON s.[SnapshotID] = p.[SnapshotID];
		
		DELETE p
		FROM [perms].[Users] p
		INNER JOIN @snapshots s ON s.[SnapshotID] = p.[SnapshotID];
		
		DELETE p
		FROM [perms].[Snapshots] p
		INNER JOIN @snapshots s ON s.[SnapshotID] = p.[ID];


		COMMIT TRANSACTION
		END TRY
	BEGIN CATCH
		ROLLBACK TRANSACTION
	END CATCH
END

GO


--If our procedure doesn't already exist, create one with a dummy query to be overwritten.
IF OBJECT_ID('perms.removeAllUsersFromDB') IS NULL
  EXEC sp_executesql N'CREATE PROCEDURE perms.removeAllUsersFromDB AS SELECT 1;';
GO

ALTER PROCEDURE [perms].[removeAllUsersFromDB] (
	@DBName NVARCHAR(128)
 )
AS

/**************************************************************************
	Author: Eric Cobb - http://www.sqlnuggets.com/
		License:
			MIT License
			Copyright (c) 2017 Eric Cobb
			View full license disclosure: https://github.com/ericcobb/SQL-Server-Metrics-Pack/blob/master/LICENSE
			
	Purpose: 
			This stored procedure is used to drop all users from a database.
			Users that own certificates, and default system users, will not be dropped.
            Users can be added back using the latest permissions snapshot for that database.

	Parameters:
			@DBName - REQUIRED - Database you wish to remove all user from.

	Usage:	
			--Remove all users from the MyDB database;
			EXEC [perms].[removeAllUsersFromDB] @DBName='MyDB';
			
***************************************************************************/

BEGIN
	SET NOCOUNT ON;
    DECLARE @Message NVARCHAR(255);
    DECLARE @sql NVARCHAR(4000);
    DECLARE @Error NVARCHAR(400);

    --ensure parameters supplied are compatible.
    SET @Error = 0;
    IF @DBName = ''
    BEGIN
		SET @Message = 'The value for parameter @DBName is not supported.' + CHAR(13) + CHAR(10)
		RAISERROR(@Message,16,1) WITH NOWAIT
		SET @Error = @@ERROR
    END

    SET @sql = N'USE ' + @DBName + ';
	'

    SET @sql = @sql + N'
			DECLARE @UserID       varchar(128)
			DECLARE @SQLstmt      varchar(255)

			PRINT ''Fix Database Users''
			PRINT ''Server:   '' + @@servername
			PRINT ''Database: '' + DB_NAME()
			
			--avoid dropping users that were creating using certificates
			DECLARE DropUserCursor CURSOR LOCAL FAST_FORWARD FOR
			SELECT p.name FROM sys.database_principals p
			LEFT JOIN sys.certificates c ON p.principal_id = c.principal_id
			WHERE p.type <> ''R''
			AND p.principal_id >=5
			AND c.principal_id IS NULL

			OPEN DropUserCursor
			FETCH NEXT FROM DropUserCursor INTO @UserID
			WHILE @@FETCH_STATUS = 0
				BEGIN
					SELECT @SQLstmt = ''exec sp_revokedbaccess '''''' + @UserID + ''''''''
				PRINT @SQLstmt
				EXEC (@SQLstmt)
				FETCH NEXT FROM DropUserCursor INTO @UserID
			END

			CLOSE DropUserCursor
			DEALLOCATE DropUserCursor
	   '
   EXECUTE sp_executesql @sql
   --PRINT @sql
 
END
GO


--If our procedure doesn't already exist, create one with a dummy query to be overwritten.
IF OBJECT_ID('perms.removeLogin') IS NULL
  EXEC sp_executesql N'CREATE PROCEDURE perms.removeLogin AS SELECT 1;';
GO

ALTER PROCEDURE [perms].[removeLogin] (
	@UserName NVARCHAR(256),
	@ExecuteScript BIT = 0,
	@DropLogin BIT = 1
)
AS

/**************************************************************************
	Author: Eric Cobb - http://www.sqlnuggets.com/
		License:
			MIT License
			Copyright (c) 2017 Eric Cobb
			View full license disclosure: https://github.com/ericcobb/SQL-Server-Metrics-Pack/blob/master/LICENSE
			
	Purpose: 
			This stored procedure is used to remove a user from all databases, then drop the login for that user.
			Users that own certificates, and default system users, will not be dropped.

	Parameters:
			@UserName - REQUIRED - the user we want to clone
			@ExecuteScript - OPTIONAL -	Flag for whether or not to actually apply the Permissions Snapshot.
										If 1: Automatically apply the permissions to the databse.
										If 0 (Default): Generates the permissions script to be reviewed/run manually.
			@DropLogin - OPTIONAL - Flag for where or not to actually drop the login after the user has been removed from all databases.

	Usage:	
			--Generate script to remove User1 from all databases and drop login;
			EXEC [perms].[removeLogin] @UserName = N'User1', @ExecuteScript = 0, @DropLogin = 1;
			
***************************************************************************/

BEGIN
	SET NOCOUNT ON;

	DECLARE @SQL NVARCHAR(4000);
	DECLARE @DBname NVARCHAR(128);

	DECLARE @dblist TABLE ([DBname] NVARCHAR(128));
	DECLARE @protectedUsers TABLE ([username] NVARCHAR(256));

	IF @ExecuteScript = 0
	BEGIN
		--SELECT 'THIS IS ONLY A TEST; THE SCRIPT HAS NOT EXECUTED AND THE USER HAS NOT BEEN REMOVED!'
		PRINT 'THIS IS ONLY A TEST; THE SCRIPT HAS NOT EXECUTED AND THE USER HAS NOT BEEN REMOVED!'
	END

	--get list of users that were creating using certificates
	INSERT INTO @protectedUsers
	SELECT distinct p.name 
	FROM sys.database_principals p
	INNER JOIN sys.certificates c ON p.principal_id = c.principal_id
	WHERE p.type <> 'R'
	
	IF @UserName IN (select coalesce(username,'N/A') from @protectedUsers)
	THROW 51000, 'This user is attached to a certificate and cannot be deleted!', 1;  
	
	--get list of system users
	INSERT INTO @protectedUsers
	SELECT  p.name 
	FROM sys.database_principals p
	WHERE p.type <> 'R'
	AND p.principal_id < 5
	
	IF @UserName IN (select username from @protectedUsers)
	THROW 51000, 'This is a system user and cannot be deleted!', 1;  
 
	--get list of databases this user has access to
	--TODO: I don't like using sp_MSforeachdb, find a replacement query
	SET @sql ='SELECT ''?'' AS DBName FROM ?.sys.database_principals WHERE name=''' + @UserName + ''''
	INSERT INTO @dblist
	EXEC sp_MSforeachdb @command1=@sql
		
	IF EXISTS (SELECT DBname FROM @dblist)
		BEGIN
			DECLARE DBList CURSOR LOCAL FAST_FORWARD FOR
			SELECT DBname FROM @dblist

			OPEN DBList
			FETCH NEXT FROM DBList INTO @DBname
			WHILE @@FETCH_STATUS = 0
			BEGIN
				SET @sql = N'USE ' + @DBName + ';'
				SET @sql = @sql + N'DROP USER ['+@UserName+']'
				PRINT 'Dropping user from ' +	+ @DBName + ';'
		
				IF @ExecuteScript = 1
					EXECUTE sp_executesql @sql
				--ELSE
				--	SELECT @sql

				FETCH NEXT FROM DBList INTO @DBname
			END

			CLOSE DBList
			DEALLOCATE DBList
		
		END
	ELSE PRINT 'User ''' +@UserName+''' Is Not Assigned To Any Databases.'

	--if the login exists, drop it!
	IF @DropLogin = 1 AND EXISTS (select loginname from master.dbo.syslogins where name = @UserName)
		BEGIN
			PRINT 'Dropping Login ' +@UserName+''
			SET @sql = N'DROP LOGIN [' +@UserName+']' 
			IF @ExecuteScript = 1
				EXECUTE sp_executesql @sql
			--ELSE
			--	SELECT @sql
		END
	ELSE 
	IF @DropLogin = 1 
	PRINT 'Login ''' +@UserName+''' Does Not Exist'
	
END
GO


--If our procedure doesn't already exist, create one with a dummy query to be overwritten.
IF OBJECT_ID('perms.restorePerms') IS NULL
  EXEC sp_executesql N'CREATE PROCEDURE perms.restorePerms AS SELECT 1;';
GO

ALTER PROCEDURE [perms].[restorePerms](
    @DBname NVARCHAR(128),
	@SnapshotID INT = NULL
 )
AS

/**************************************************************************
	Author: Eric Cobb - http://www.sqlnuggets.com/
		License:
			MIT License
			Copyright (c) 2017 Eric Cobb
			View full license disclosure: https://github.com/ericcobb/SQL-Server-Metrics-Pack/blob/master/LICENSE
			
	Purpose: 
			This stored procedure is used to remove all users from a database,
            then Users will be added back using the latest permissions snapshot for that database.

	Parameters:
			@DBName - REQUIRED - Name of the Database you want to drop users and apply a Permissions Snapshot to.
			@SnapshotID - OPTIONAL - ID of the specific Snapshot you want to apply.

	Usage:	
			--Drop all users from MyDB and restore the latest Permissions Snapshot for that database;
			EXEC [perms].[restorePerms] @DBName='MyDB';
			
***************************************************************************/

BEGIN
	SET NOCOUNT ON;

	--Drop all Users from the database
	EXEC perms.removeAllUsersFromDB @DBname

	--Restore Users from latest snapshot
	EXEC perms.applyPermissions 
		@DBName = @DBname,
		@SnapshotID = @SnapshotID,
		@CreateLogins = 1,
		@ExecuteScript = 1

END

GO


/**************************************************************************
	Create Views
***************************************************************************/

--If our view doesn't already exist, create one with a dummy query to be overwritten.
IF OBJECT_ID('perms.vwPerms_listCurrentSnapshots') IS NULL
  EXEC sp_executesql N'CREATE VIEW [perms].[vwPerms_listCurrentSnapshots] AS SELECT [DB] = DB_NAME();';
GO

ALTER VIEW [perms].[vwPerms_listCurrentSnapshots] 

AS
	/**************************************************************************
		Author: Eric Cobb - http://www.sqlnuggets.com/
		License:
				MIT License
				Copyright (c) 2017 Eric Cobb
				View full license disclosure: https://github.com/ericcobb/SQL-Server-Metrics-Pack/blob/master/LICENSE
		Purpose: 
				This view returns a list of the most recent Permissions Snapshots for each database
					
	***************************************************************************/

SELECT ID, [DatabaseName], [CaptureDate]
FROM(SELECT ID, [DatabaseName], [CaptureDate] 
		,ROW_NUMBER() OVER (PARTITION BY [DatabaseName] ORDER BY [CaptureDate] DESC) AS rn
	FROM perms.snapshots
) s
WHERE s.rn = 1

GO


--If our view doesn't already exist, create one with a dummy query to be overwritten.
--IF OBJECT_ID('perms.vwPerms_listCurrentUserPermissions') IS NULL
--  EXEC sp_executesql N'CREATE VIEW [perms].[vwPerms_listCurrentUserPermissions] AS SELECT [DB] = DB_NAME();';
--GO

--ALTER VIEW perms.vwPerms_listCurrentUserPermissions
--AS
--	/**************************************************************************
--		Author: Eric Cobb - http://www.sqlnuggets.com/
--		License:
--				MIT License
--				Copyright (c) 2017 Eric Cobb
--				View full license disclosure: https://github.com/ericcobb/SQL-Server-Metrics-Pack/blob/master/LICENSE
--		Purpose: 
--				This view returns a list of the most recent Permissions Snapshots for each database, displaying users and their assigned permissions
					
--	***************************************************************************/

--	SELECT TOP 100 PERCENT [SnapshotID] = ID, [DatabaseName], [CaptureDate]
--			,rm.[username]
--			,rm.[PermType]
--			,rm.[Perm]
--	FROM(SELECT ID, [DatabaseName], [CaptureDate] 
--			,ROW_NUMBER() OVER (PARTITION BY [DatabaseName] ORDER BY [CaptureDate] DESC) AS rn
--		FROM perms.snapshots
--		) s
--	INNER JOIN (SELECT [PermType] = 'Role Memberships', [Perm] = rolename, username, SnapshotID 
--				FROM perms.RoleMemberships
--				UNION 
--				SELECT [PermType] = 'Database Permission', [Perm] = StateDesc + ' ' + PermissionName, username, SnapshotID 
--				FROM perms.DatabasePermissions
--				UNION 
--				SELECT [PermType] = 'Schema Permission', [Perm] = StateDesc + ' ' + PermissionName + ' ON ['  + schemaname + ']', username, SnapshotID 
--				FROM perms.SchemaPermissions
--				UNION 
--				SELECT [PermType] = 'Object Permission', [Perm] = CASE WHEN columnname IS NULL THEN SPACE(1) ELSE ' (' + QUOTENAME(columnname) + ')' END
--																	+ StateDesc + ' ' + PermissionName + ' ON [' + schemaname + '.' + objectname + ']'
--														, username, SnapshotID 
--				FROM perms.ObjectPermissions
--				) rm ON rm.SnapshotID = s.ID
--	WHERE s.rn = 1
--	ORDER BY [DatabaseName],[username],[PermType],[Perm];

--GO


--If our view doesn't already exist, create one with a dummy query to be overwritten.
IF OBJECT_ID('perms.vwPerms_listCurrentDBPermissions') IS NULL
  EXEC sp_executesql N'CREATE VIEW [perms].[vwPerms_listCurrentDBPermissions] AS SELECT [DB] = DB_NAME();';
GO


ALTER VIEW [perms].[vwPerms_listCurrentDBPermissions]
AS
	/**************************************************************************
		Author: Eric Cobb - http://www.sqlnuggets.com/
		License:
				MIT License
				Copyright (c) 2017 Eric Cobb
				View full license disclosure: https://github.com/ericcobb/SQL-Server-Metrics-Pack/blob/master/LICENSE
		Purpose: 
				This view returns a list of the most recent Permissions Snapshots for each database, displaying users and their assigned permissions.					
	***************************************************************************/

	SELECT TOP 100 PERCENT [SnapshotID] = ID, [CaptureDate], [DatabaseName]
			,rm.[username]
			,rm.[PermType]
			,rm.[Perm]
	FROM(SELECT ID, [DatabaseName], [CaptureDate] 
			,ROW_NUMBER() OVER (PARTITION BY [DatabaseName] ORDER BY [CaptureDate] DESC) AS rn
		FROM perms.snapshots
		) s
		INNER JOIN (SELECT [PermType] = 'User-Login Mapping'
							,[UserName] 
							,[Perm] = ' FROM LOGIN ' + [loginname]
							,[SnapshotID]
					 FROM [perms].[Users] u
					UNION
					SELECT [PermType] = CASE WHEN r.[roletype] = 'R' THEN 'Database Role' ELSE ' Application Role' END
							,[UserName] = [rolename]
							,[Perm] = NULL
							,[SnapshotID]
					FROM [perms].[Roles] r
					UNION 
					SELECT [PermType] = 'Role Memberships'
							,[UserName]
							,[Perm] = [rolename]
							,[SnapshotID]
					FROM [perms].[RoleMemberships] rm
					UNION
					SELECT [PermType] = 'Object Permission'
							,[UserName]
							,[Perm] = CASE WHEN state <> 'W' THEN [StateDesc] + SPACE(1) ELSE 'GRANT ' END
										+ [PermissionName] 
										+ ' ON [' +  [schemaname] + '].[' + [objectname] + '] TO [' + [username] + ']'
										+ CASE WHEN [state] <> 'W' THEN SPACE(0) ELSE ' (WITH GRANT OPTION)' END
							,[SnapshotID]
					FROM [perms].[ObjectPermissions] op
					UNION 
					SELECT [PermType] = 'Schema Permission'
							,[UserName]
							,[Perm] = CASE WHEN [state] <> 'W' THEN [StateDesc] + SPACE(1) ELSE 'GRANT ' END
										+ [PermissionName] 
										+ ' ON [' + [schemaname] + '] TO [' + [username] + ']'
										+ CASE WHEN [state] <> 'W' THEN SPACE(0) ELSE ' (WITH GRANT OPTION)' END
							,[SnapshotID]
					FROM [perms].[SchemaPermissions] 
					UNION
					SELECT [PermType] = 'Database Permission'
							,[UserName]
							,[Perm] = StateDesc + ' ' + PermissionName
							,[SnapshotID]
					FROM perms.DatabasePermissions
					) rm ON rm.[SnapshotID] = s.ID
	WHERE s.rn = 1
	ORDER BY [DatabaseName],[username],[PermType],[Perm];


GO
