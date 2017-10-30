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
package com.facebook.presto.hive.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

public class SecurityDatabaseConnection
{
    // init database constants
    private String databaseDriver;
    private String databaseUrl;
    private String databaseUsername;
    private String databasePassword;

    public SecurityDatabaseConnection(String databaseDriver, String databaseUrl, String databaseUsername, String databasePassword)
    {
        this.databaseDriver = databaseDriver;
        this.databaseUrl = databaseUrl;
        this.databaseUsername = databaseUsername;
        this.databasePassword = databasePassword;
    }

    // init connection object
    private Connection connection;
    // init properties object
    private Properties properties;

    // create properties
    private Properties getProperties()
    {
        if (properties == null) {
            properties = new Properties();
            properties.setProperty("user", this.databaseUsername);
            properties.setProperty("password", this.databasePassword);
            properties.setProperty("MaxPooledStatements", "250");
        }
        return properties;
    }

    // connect database
    public Connection connect()
    {
        if (connection == null) {
            try {
                Class.forName(this.databaseDriver);
                connection = DriverManager.getConnection(this.databaseUrl, getProperties());
            }
            catch (ClassNotFoundException | SQLException e) {
                e.printStackTrace();
            }
        }
        return connection;
    }

    // disconnect database
    public void disconnect()
    {
        if (connection != null) {
            try {
                connection.close();
                connection = null;
            }
            catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
}
