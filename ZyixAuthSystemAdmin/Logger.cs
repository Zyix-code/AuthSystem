using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ZyixAuthSystemAdmin
{
    public class Logger
    {
        private string connectionString;

        public Logger(string dbConnectionString)
        {
            connectionString = dbConnectionString;
        }

        public void LogTransaction(int userID, string logLevel, string logDescription)
        {
            using (SqlConnection connection = new SqlConnection(connectionString))
            {
                connection.Open();

                string insertQuery = "INSERT INTO Logs (UserID, LogLevel, LogDescription, LogDate) VALUES (@UserID, @LogLevel, @LogDescription, GETDATE())";

                using (SqlCommand cmd = new SqlCommand(insertQuery, connection))
                {
                    cmd.Parameters.AddWithValue("@UserID", userID);
                    cmd.Parameters.AddWithValue("@LogLevel", logLevel);
                    cmd.Parameters.AddWithValue("@LogDescription", logDescription);
                    cmd.ExecuteNonQuery();
                }

                connection.Close();
            }
        }
    }
}
