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

import io.airlift.configuration.Config;
import io.airlift.configuration.ConfigDescription;

public class SentrySecurityConfig
{
    private String databaseDriver;
    private String databaseUrl;
    private String databaseUsername;
    private String databasePassword;
    private String serverName;
    private String adminRole;

    public String getDatabaseDriver()
    {
        return this.databaseDriver;
    }

    @Config("hive.sentry.database.driver")
    @ConfigDescription("Database Driver")
    public SentrySecurityConfig setDatabaseDriver(String databaseDriver)
    {
        this.databaseDriver = databaseDriver;
        return this;
    }

    public String getDatabaseUrl()
    {
        return this.databaseUrl;
    }

    @Config("hive.sentry.database.url")
    @ConfigDescription("Database URL")
    public SentrySecurityConfig setDatabaseUrl(String databaseUrl)
    {
        this.databaseUrl = databaseUrl;
        return this;
    }

    public String getDatabaseUsername()
    {
        return this.databaseUsername;
    }

    @Config("hive.sentry.database.username")
    @ConfigDescription("Database username")
    public SentrySecurityConfig setDatabaseUsername(String databaseUsername)
    {
        this.databaseUsername = databaseUsername;
        return this;
    }

    public String getDatabasePassword()
    {
        return this.databasePassword;
    }

    @Config("hive.sentry.database.password")
    @ConfigDescription("Database password")
    public SentrySecurityConfig setDatabasePassword(String databasePassword)
    {
        this.databasePassword = databasePassword;
        return this;
    }

    public String getServerName()
    {
        return this.serverName;
    }

    @Config("hive.sentry.server.name")
    @ConfigDescription("Server name")
    public SentrySecurityConfig setServerName(String serverName)
    {
        this.serverName = serverName;
        return this;
    }

    public String getAdminRole()
    {
        return this.adminRole;
    }

    @Config("hive.sentry.admin.role")
    @ConfigDescription("Admin role")
    public SentrySecurityConfig setAdminRole(String adminRole)
    {
        this.adminRole = adminRole;
        return this;
    }
}
