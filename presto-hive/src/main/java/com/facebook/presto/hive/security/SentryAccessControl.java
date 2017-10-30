/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.facebook.presto.hive.security;

import com.facebook.presto.hive.metastore.HivePrivilegeInfo;
import com.facebook.presto.hive.util.SecurityDatabaseConnection;
import com.facebook.presto.spi.SchemaTableName;
import com.facebook.presto.spi.connector.ConnectorAccessControl;
import com.facebook.presto.spi.connector.ConnectorTransactionHandle;
import com.facebook.presto.spi.security.Identity;
import com.facebook.presto.spi.security.Privilege;
import com.google.common.collect.ImmutableSet;

import javax.inject.Inject;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.facebook.presto.hive.metastore.HivePrivilegeInfo.HivePrivilege.DELETE;
import static com.facebook.presto.hive.metastore.HivePrivilegeInfo.HivePrivilege.INSERT;
import static com.facebook.presto.hive.metastore.HivePrivilegeInfo.HivePrivilege.OWNERSHIP;
import static com.facebook.presto.hive.metastore.HivePrivilegeInfo.HivePrivilege.SELECT;
import static com.facebook.presto.hive.metastore.HivePrivilegeInfo.toHivePrivilege;
import static com.facebook.presto.spi.security.AccessDeniedException.denyAddColumn;
import static com.facebook.presto.spi.security.AccessDeniedException.denyCreateSchema;
import static com.facebook.presto.spi.security.AccessDeniedException.denyCreateTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyCreateView;
import static com.facebook.presto.spi.security.AccessDeniedException.denyCreateViewWithSelect;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDeleteTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDropColumn;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDropSchema;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDropTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyDropView;
import static com.facebook.presto.spi.security.AccessDeniedException.denyGrantTablePrivilege;
import static com.facebook.presto.spi.security.AccessDeniedException.denyInsertTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyRenameColumn;
import static com.facebook.presto.spi.security.AccessDeniedException.denyRenameSchema;
import static com.facebook.presto.spi.security.AccessDeniedException.denyRenameTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denyRevokeTablePrivilege;
import static com.facebook.presto.spi.security.AccessDeniedException.denySelectTable;
import static com.facebook.presto.spi.security.AccessDeniedException.denySelectView;
import static com.facebook.presto.spi.security.AccessDeniedException.denySetCatalogSessionProperty;
import static java.util.Objects.requireNonNull;

public class SentryAccessControl
        implements ConnectorAccessControl
{
    private final SecurityDatabaseConnection databaseConnection;
    private final String databaseDriver;
    private final String databaseUrl;
    private final String databaseUsername;
    private final String databasePassword;
    private final String serverName;
    private final String adminRole;

    @Inject
    public SentryAccessControl(SentrySecurityConfig securityConfig)
    {
        requireNonNull(securityConfig, "Security Config is null");
        databaseDriver = requireNonNull(securityConfig.getDatabaseDriver(), "Database Driver is null");
        databaseUrl = requireNonNull(securityConfig.getDatabaseUrl(), "Database Url is null");
        databaseUsername = requireNonNull(securityConfig.getDatabaseUsername(), "Database Username is null");
        databasePassword = requireNonNull(securityConfig.getDatabasePassword(), "Database Password is null");
        serverName = requireNonNull(securityConfig.getServerName(), "Server Name is null");
        adminRole = requireNonNull(securityConfig.getAdminRole(), "Admin Role is null");
        databaseConnection = new SecurityDatabaseConnection(
                databaseDriver, databaseUrl, databaseUsername, databasePassword);
    }

    @Override
    public void checkCanCreateSchema(ConnectorTransactionHandle transactionHandle, Identity identity, String schemaName)
    {
        if (!isAdmin(identity)) {
            denyCreateSchema(schemaName);
        }
    }

    @Override
    public void checkCanDropSchema(ConnectorTransactionHandle transactionHandle, Identity identity, String schemaName)
    {
        if (!isDatabaseOwner(identity, schemaName)) {
            denyDropSchema(schemaName);
        }
    }

    @Override
    public void checkCanRenameSchema(ConnectorTransactionHandle transactionHandle, Identity identity, String schemaName, String newSchemaName)
    {
        if (!isAdmin(identity) || !isDatabaseOwner(identity, schemaName)) {
            denyRenameSchema(schemaName, newSchemaName);
        }
    }

    @Override
    public void checkCanShowSchemas(ConnectorTransactionHandle transactionHandle, Identity identity)
    {
    }

    @Override
    public Set<String> filterSchemas(ConnectorTransactionHandle transactionHandle, Identity identity, Set<String> schemaNames)
    {
        return schemaNames;
    }

    @Override
    public void checkCanCreateTable(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!isDatabaseOwner(identity, tableName.getSchemaName())) {
            denyCreateTable(tableName.toString());
        }
    }

    @Override
    public void checkCanDropTable(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, OWNERSHIP)) {
            denyDropTable(tableName.toString());
        }
    }

    @Override
    public void checkCanRenameTable(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName, SchemaTableName newTableName)
    {
        if (!checkTablePermission(identity, tableName, OWNERSHIP)) {
            denyRenameTable(tableName.toString(), newTableName.toString());
        }
    }

    @Override
    public void checkCanShowTablesMetadata(ConnectorTransactionHandle transactionHandle, Identity identity, String schemaName)
    {
    }

    @Override
    public Set<SchemaTableName> filterTables(ConnectorTransactionHandle transactionHandle, Identity identity, Set<SchemaTableName> tableNames)
    {
        return tableNames;
    }

    @Override
    public void checkCanAddColumn(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, OWNERSHIP)) {
            denyAddColumn(tableName.toString());
        }
    }

    @Override
    public void checkCanDropColumn(ConnectorTransactionHandle transactionHandle, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, OWNERSHIP)) {
            denyDropColumn(tableName.toString());
        }
    }

    @Override
    public void checkCanRenameColumn(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, OWNERSHIP)) {
            denyRenameColumn(tableName.toString());
        }
    }

    @Override
    public void checkCanSelectFromTable(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, SELECT)) {
            denySelectTable(tableName.toString());
        }
    }

    @Override
    public void checkCanInsertIntoTable(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, INSERT)) {
            denyInsertTable(tableName.toString());
        }
    }

    @Override
    public void checkCanDeleteFromTable(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, DELETE)) {
            denyDeleteTable(tableName.toString());
        }
    }

    @Override
    public void checkCanCreateView(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName viewName)
    {
        if (!isDatabaseOwner(identity, viewName.getSchemaName())) {
            denyCreateView(viewName.toString());
        }
    }

    @Override
    public void checkCanDropView(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName viewName)
    {
        if (!checkTablePermission(identity, viewName, OWNERSHIP)) {
            denyDropView(viewName.toString());
        }
    }

    @Override
    public void checkCanSelectFromView(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName viewName)
    {
        if (!checkTablePermission(identity, viewName, SELECT)) {
            denySelectView(viewName.toString());
        }
    }

    @Override
    public void checkCanCreateViewWithSelectFromTable(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName tableName)
    {
        if (!checkTablePermission(identity, tableName, SELECT)) {
            denySelectTable(tableName.toString());
        }
        else if (!getGrantOptionForPrivilege(identity, toHivePrivilege(Privilege.SELECT), tableName)) {
            denyCreateViewWithSelect(tableName.toString());
        }
    }

    @Override
    public void checkCanCreateViewWithSelectFromView(ConnectorTransactionHandle transaction, Identity identity, SchemaTableName viewName)
    {
        if (!checkTablePermission(identity, viewName, SELECT)) {
            denySelectView(viewName.toString());
        }
        if (!getGrantOptionForPrivilege(identity, toHivePrivilege(Privilege.SELECT), viewName)) {
            denyCreateViewWithSelect(viewName.toString());
        }
    }

    @Override
    public void checkCanSetCatalogSessionProperty(Identity identity, String propertyName)
    {
        // TODO: when this is updated to have a transaction, use isAdmin()
        if (!isAdmin(identity)) {
            denySetCatalogSessionProperty(serverName, propertyName);
        }
    }

    @Override
    public void checkCanGrantTablePrivilege(ConnectorTransactionHandle transaction, Identity identity, Privilege privilege, SchemaTableName tableName, String grantee, boolean withGrantOption)
    {
        if (checkTablePermission(identity, tableName, OWNERSHIP)) {
            return;
        }

        HivePrivilegeInfo.HivePrivilege hivePrivilege = toHivePrivilege(privilege);
        if (hivePrivilege == null || !getGrantOptionForPrivilege(identity, hivePrivilege, tableName)) {
            denyGrantTablePrivilege(privilege.name(), tableName.toString());
        }
    }

    @Override
    public void checkCanRevokeTablePrivilege(ConnectorTransactionHandle transaction, Identity identity, Privilege privilege, SchemaTableName tableName, String revokee, boolean grantOptionFor)
    {
        if (checkTablePermission(identity, tableName, OWNERSHIP)) {
            return;
        }

        HivePrivilegeInfo.HivePrivilege hivePrivilege = toHivePrivilege(privilege);
        if (hivePrivilege == null || !getGrantOptionForPrivilege(identity, hivePrivilege, tableName)) {
            denyRevokeTablePrivilege(privilege.name(), tableName.toString());
        }
    }

    private boolean getGrantOptionForPrivilege(Identity identity, HivePrivilegeInfo.HivePrivilege privilege, SchemaTableName tableName)
    {
        String group = identity.getUser();

        String groupId = requireNonNull(checkGroup(group), "User doesn't belong to any group");

        List<String> rolesId = checkRole(groupId);

        if (rolesId.isEmpty()) {
            throw new NullPointerException("User doesn't have any roles");
        }

        List<String> privilegesId = checkPrivilege(rolesId);

        if (rolesId.isEmpty()) {
            throw new NullPointerException("User doesn't have enough privileges");
        }

        return checkPermissions(privilegesId, tableName.getSchemaName(), tableName.getTableName(), privilege);
    }

    private boolean checkTablePermission(Identity identity, SchemaTableName tableName, HivePrivilegeInfo.HivePrivilege... requiredPrivileges)
    {
        String group = identity.getUser();

        String groupId = requireNonNull(checkGroup(group), "User doesn't belong to any group");

        List<String> rolesId = checkRole(groupId);

        if (rolesId.isEmpty()) {
            throw new NullPointerException("User doesn't have any roles");
        }

        List<String> privilegesId = checkPrivilege(rolesId);

        if (rolesId.isEmpty()) {
            throw new NullPointerException("User doesn't have enough privileges");
        }

        return checkPermissions(privilegesId, tableName.getSchemaName(), tableName.getTableName(), requiredPrivileges);
    }

    private boolean checkDatabasePermission(Identity identity, String schemaName, HivePrivilegeInfo.HivePrivilege... requiredPrivileges)
    {
        String group = identity.getUser();

        String groupId = requireNonNull(checkGroup(group), "User doesn't belong to any group");

        List<String> rolesId = checkRole(groupId);

        if (rolesId.isEmpty()) {
            throw new NullPointerException("User doesn't have any roles");
        }

        List<String> privilegesId = checkPrivilege(rolesId);

        if (rolesId.isEmpty()) {
            throw new NullPointerException("User doesn't have enough privileges");
        }

        return checkPermissions(privilegesId, schemaName, null, requiredPrivileges);
    }

    private String checkGroup(String group)
    {
        String sql = "SELECT * FROM SENTRY_GROUP WHERE GROUP_NAME = ?";
        String groupId = null;
        try {
            PreparedStatement statement = databaseConnection.connect().prepareStatement(sql);
            statement.setString(1, group);
            ResultSet result = statement.executeQuery();
            if (result.next()) {
                groupId = result.getString("GROUP_ID");
            }
        }
        catch (SQLException e) {
            e.printStackTrace();
        }
        finally {
            databaseConnection.disconnect();
        }

        return groupId;
    }

    private List<String> checkRole(String groupId)
    {
        String sql = "SELECT * FROM SENTRY_ROLE_GROUP_MAP where GROUP_ID = ?";
        LinkedList<String> rolesId = null;
        try {
            PreparedStatement statement = databaseConnection.connect().prepareStatement(sql);
            statement.setString(1, groupId);
            ResultSet result = statement.executeQuery();
            rolesId = new LinkedList<String>();
            while (result.next()) {
                rolesId.add(result.getString("ROLE_ID"));
            }
        }
        catch (SQLException e) {
            e.printStackTrace();
        }
        finally {
            databaseConnection.disconnect();
        }

        return rolesId;
    }

    private Set<String> getRoles(List<String> rolesId)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT * FROM SENTRY_ROLE where ROLE_ID = ?");
        Integer i;
        for (i = 1; i < rolesId.size(); i++) {
            sb.append(" OR ROLE_ID = ?");
        }
        String sql = sb.toString();
        HashSet<String> roles = null;
        try {
            PreparedStatement statement = databaseConnection.connect().prepareStatement(sql);
            i = 1;
            for (String roleId : rolesId) {
                statement.setString(i, roleId);
                i++;
            }
            ResultSet result = statement.executeQuery();
            roles = new HashSet<String>();
            while (result.next()) {
                roles.add(result.getString("ROLE_NAME"));
            }
        }
        catch (SQLException e) {
            e.printStackTrace();
        }
        finally {
            databaseConnection.disconnect();
        }

        return roles;
    }

    private List<String> checkPrivilege(List<String> rolesId)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT * FROM SENTRY_ROLE_DB_PRIVILEGE_MAP where ROLE_ID = ?");
        Integer i;
        for (i = 1; i < rolesId.size(); i++) {
            sb.append(" OR ROLE_ID = ?");
        }
        String sql = sb.toString();
        LinkedList<String> privilegesId = null;
        try {
            PreparedStatement statement = databaseConnection.connect().prepareStatement(sql);
            i = 1;
            for (String roleId : rolesId) {
                statement.setString(i, roleId);
                i++;
            }
            ResultSet result = statement.executeQuery();
            privilegesId = new LinkedList<String>();
            while (result.next()) {
                privilegesId.add(result.getString("DB_PRIVILEGE_ID"));
            }
        }
        catch (SQLException e) {
            e.printStackTrace();
        }
        finally {
            databaseConnection.disconnect();
        }

        return privilegesId;
    }

    private boolean checkPermissions(List<String> privilegesId, String schemaName, String tableName, HivePrivilegeInfo.HivePrivilege... requiredPrivileges)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT * FROM SENTRY_DB_PRIVILEGE where DB_PRIVILEGE_ID = ?");
        Integer i;
        for (i = 1; i < privilegesId.size(); i++) {
            sb.append(" OR DB_PRIVILEGE_ID = ?");
        }
        String sql = sb.toString();
        try {
            PreparedStatement statement = databaseConnection.connect().prepareStatement(sql);
            i = 1;
            for (String roleId : privilegesId) {
                statement.setString(i, roleId);
                i++;
            }
            ImmutableSet.Builder<HivePrivilegeInfo> privileges = ImmutableSet.builder();
            ResultSet result = statement.executeQuery();
            while (result.next()) {
                String scope = result.getString("PRIVILEGE_SCOPE");
                String scopeName = result.getString("SERVER_NAME");
                String dbName = result.getString("DB_NAME");
                String tbName = result.getString("TABLE_NAME");
                String action = result.getString("ACTION");
                String grantOption = result.getString("WITH_GRANT_OPTION");

                boolean checkServerName = scopeName.equals(serverName);

                boolean withGrantOption = grantOption.equals("Y");

                Set<HivePrivilegeInfo.HivePrivilege> privilegeSet = getHivePrivilegeInfoSet(action, withGrantOption).stream()
                        .map(HivePrivilegeInfo::getHivePrivilege)
                        .collect(Collectors.toSet());

                switch (scope) {
                    case "SERVER":
                        if (checkServerName) {
                            return privilegeSet.containsAll(ImmutableSet.copyOf(requiredPrivileges));
                        }
                        break;
                    case "DATABASE":
                        if (checkServerName && schemaName.equals(dbName)) {
                            return privilegeSet.containsAll(ImmutableSet.copyOf(requiredPrivileges));
                        }
                        break;
                    case "TABLE":
                        if (checkServerName && schemaName.equals(dbName)
                                && tbName.equals(tableName)) {
                            return privilegeSet.containsAll(ImmutableSet.copyOf(requiredPrivileges));
                        }
                        break;
                    default:
                        break;
                }
            }
        }
        catch (SQLException e) {
            e.printStackTrace();
        }
        finally {
            databaseConnection.disconnect();
        }

        return false;
    }

    private Set<HivePrivilegeInfo> getHivePrivilegeInfoSet(String action, boolean withGrantOption)
    {
        switch (action) {
            case "all":
                return Arrays.stream(HivePrivilegeInfo.HivePrivilege.values())
                        .map(hivePrivilege -> new HivePrivilegeInfo(hivePrivilege, withGrantOption))
                        .collect(Collectors.toSet());
            case "*":
                return Arrays.stream(HivePrivilegeInfo.HivePrivilege.values())
                        .map(hivePrivilege -> new HivePrivilegeInfo(hivePrivilege, withGrantOption))
                        .collect(Collectors.toSet());
            case "select":
                return ImmutableSet.of(new HivePrivilegeInfo(SELECT, withGrantOption));
            case "insert":
                return ImmutableSet.of(new HivePrivilegeInfo(INSERT, withGrantOption));
        }
        return ImmutableSet.of();
    }

    private boolean isDatabaseOwner(Identity identity, String schemaName)
    {
        return checkDatabasePermission(identity, schemaName, null, OWNERSHIP);
    }

    private boolean isAdmin(Identity identity)
    {
        if (identity.getPrincipal().isPresent()) {
            String group = identity.getPrincipal().get().getName();

            if (group == null) {
                return false;
            }

            String groupId = checkGroup(group);

            if (groupId == null) {
                return false;
            }

            List<String> rolesId = checkRole(groupId);

            if (rolesId.isEmpty()) {
                return false;
            }

            Set<String> roles = getRoles(rolesId);

            return !roles.isEmpty() && roles.contains(adminRole);
        }
        return false;
    }
}
