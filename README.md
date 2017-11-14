# SQL Server Permissions Manager
SQL Server Permission Manager is a suite of scripts that allows you to take "snapshots" of users and permissions across any or all of the databases on your SQL Server.  These snapshots then allow you to:

- Restore existing user permissions to a previous snapshot
- Script out permissions for an individual user or all users in a database
- Create a new user by cloning the permissions of an existing user
- Remove all users and their permissions from a database
- Remove a login from the server and all of its permissions from all databases
## How It Works
SQL Server Permissions Manager creates a "perms" schema in your database, and creates all of its objects there.  Tables are created for storing the permission snapshots, and stored procedures are used for gathering and using the snapshot data.

## Installation
Simply run the *permissions-manager-install.sql* file, specifying which database you want the objects to be created in, and then schedule either the *perms.createSnapshot* (for a specific database) or *perms.snapshotAllDBs* (for all databases) Stored Procedure to run on a regular basis (I recommend nightly). On each scheduled run, the Procedure will create a snapshot of the current permissions. Once a snapshot has been created, you can call the other Procedures to use that snapshot.

## Stored Procedures
Below is a listing of the stored procedures created by SQL Server Permission Manager, and brief description of what each procedure is used for.  More detailed decriptions and examples are in the procedure header comments. 
#### perms.applyPermissions
This stored procedure is used to apply a Permissions Snapshot to a specified database; If a Snapshot ID is specified, it will restore that Snapshot, otherwise it defaults to the most recent Snapshot for the specified database;
#### perms.clonePermissions
This stored procedure is used to copy all of the permissions from a given user and assign those permissions to another user.  It will do this for every database on a server, so if a user has permissions on 3 databases, the new user and permissions will be added to those 3 databases.
#### perms.createSnapshot
This stored procedure is used to create a snapshot of the current permissions in a given database
#### perms.purgeSnapshots
This stored procedure is used to purge old Permission Snapshots from the database
#### perms.removeAllUsersFromDB
This stored procedure is used to drop all users from a database.  Users that own certificates, and default system users, will not be dropped.  Users can be added back using the latest permissions snapshot for that database.
#### perms.removeLogin
This stored procedure is used to remove a user from all databases, then drop the login for that user.  Users that own certificates, and default system users, will not be dropped.
#### perms.restorePerms
This stored procedure is used to remove all users from a database, then Users will be added back using the specified (or latest) permissions snapshot for that database.
#### perms.snapshotAllDBs
This stored procedure is used to create a snapshot of the current permissions in all databases on a server.
