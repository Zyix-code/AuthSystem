using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace ZyixAuthSystemUsers
{
    class Program
    {
        static void Main()
        {
            try
            {
                Console.Clear();
                Console.Title = "Zyix Auth System - User Login Panel";
                if (IsAlreadyRunning())
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("You can only open one instance of the application at a time!");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.WriteLine("Press any key to exit.");
                    Console.ReadKey();
                    return;
                }
                string userHwid = GetHardwareId();
                string userMotherboardId = GetMotherboardId();
                string userGetProcessorId = GetProcessorId();
                string userMacAddress = GetMacAddress();
                string userLocalIpAddress = GetLocalIpAddress();
                string userPublicIpAddress = GetPublicIpAddress();
                Console.WriteLine("");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine(" ███████╗██╗░░░██╗██╗██╗░░██╗  ░█████╗░██╗░░░██╗████████╗██╗░░██╗");
                Console.WriteLine(" ╚════██║╚██╗░██╔╝██║╚██╗██╔╝  ██╔══██╗██║░░░██║╚══██╔══╝██║░░██║");
                Console.WriteLine(" ░░███╔═╝░╚████╔╝░██║░╚███╔╝░  ███████║██║░░░██║░░░██║░░░███████║");
                Console.WriteLine(" ██╔══╝░░░░╚██╔╝░░██║░██╔██╗░  ██╔══██║██║░░░██║░░░██║░░░██╔══██║");
                Console.WriteLine(" ███████╗░░░██║░░░██║██╔╝╚██╗  ██║░░██║╚██████╔╝░░░██║░░░██║░░██║");
                Console.WriteLine(" ╚══════╝░░░╚═╝░░░╚═╝╚═╝░░╚═╝  ╚═╝░░╚═╝░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝");
                Console.WriteLine(" ────────────────────────────────────────────────────────────────");
                Console.WriteLine("      ░██████╗██╗░░░██╗░██████╗████████╗███████╗███╗░░░███╗");
                Console.WriteLine("      ██╔════╝╚██╗░██╔╝██╔════╝╚══██╔══╝██╔════╝████╗░████║");
                Console.WriteLine("      ╚█████╗░░╚████╔╝░╚█████╗░░░░██║░░░█████╗░░██╔████╔██║");
                Console.WriteLine("      ░╚═══██╗░░╚██╔╝░░░╚═══██╗░░░██║░░░██╔══╝░░██║╚██╔╝██║");
                Console.WriteLine("      ██████╔╝░░░██║░░░██████╔╝░░░██║░░░███████╗██║░╚═╝░██║");
                Console.WriteLine("      ╚═════╝░░░░╚═╝░░░╚═════╝░░░░╚═╝░░░╚══════╝╚═╝░░░░░╚═╝");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("");
                Console.WriteLine("User information;");
                Console.WriteLine(" HWID: " + userHwid);
                Console.WriteLine(" Motherboard ID: " + userMotherboardId);
                Console.WriteLine(" Processor ID: " + userGetProcessorId);
                Console.WriteLine(" MAC Address: " + userMacAddress);
                Console.WriteLine(" Local IPv4 Address: " + userLocalIpAddress);
                Console.WriteLine(" Public IP Address: " + userPublicIpAddress);
                Console.ForegroundColor = ConsoleColor.White;

                if (LoginUsers())
                {
                    Console.WriteLine("Welcome to the Users Panel!");

                    using (SqlConnection connection = new SqlConnection(AppSettings.DbConnectionString))
                    {
                        if (connection.State == ConnectionState.Closed)
                            connection.Open();
                        Thread.Sleep(500);
                        UserMenu(connection);

                        connection.Close();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in Login: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                string userPublicIpAddress = GetPublicIpAddress();
                FileLogger logger = new FileLogger("Logs.log");
                logger.LogError($"An error occurred in Login: {ex.Message}. User IP: {userPublicIpAddress}", "ERROR");
                Console.WriteLine("Press any key to exit.");
                Console.ReadKey();
            }
        }
        private static string loggedInUsername = "";
        static bool LoginUsers()
        {
            string username, enteredPassword;
            const int maxFailedAttempts = 3;

            do
            {
                try
                {
                    Console.WriteLine();
                    Console.Write("Username: ");
                    username = Console.ReadLine();

                    Console.Write("Password: ");
                    ConsoleKeyInfo key = Console.ReadKey(true);
                    enteredPassword = "";

                    while (key.Key != ConsoleKey.Enter)
                    {
                        if (key.Key != ConsoleKey.Backspace)
                        {
                            enteredPassword += key.KeyChar;
                            Console.Write("*");
                        }
                        else if (enteredPassword.Length > 0)
                        {
                            enteredPassword = enteredPassword.Substring(0, enteredPassword.Length - 1);
                            Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                            Console.Write(" ");
                            Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        }

                        key = Console.ReadKey(true);
                    }
                    Console.WriteLine();

                    if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(enteredPassword))
                    {
                        Console.WriteLine("Username and password cannot be empty. Please try again.");
                    }
                    else
                    {
                        using (SqlConnection connection = new SqlConnection(AppSettings.DbConnectionString))
                        {
                            if (connection.State == ConnectionState.Closed)
                                connection.Open();

                            string storedPassword = GetStoredPassword(username, connection);

                            if (storedPassword != null)
                            {
                                if (CheckPassword(enteredPassword, storedPassword))
                                {
                                    string userHwid = GetHardwareId();
                                    string userMacAddress = GetMacAddress();
                                    string userProcessorId = GetProcessorId();
                                    string userMotherboardId = GetMotherboardId();
                                    string userLocalIpAddress = GetLocalIpAddress();
                                    string userPublicIpAddress = GetPublicIpAddress();
                                    int userID = GetUserId(connection, username); 
                                    UpdateUserHardwareInfo(connection, username, userHwid, userMacAddress, userLocalIpAddress, userPublicIpAddress, userMotherboardId, userProcessorId);
                                    UpdateIpAddress(username, userLocalIpAddress, userPublicIpAddress, connection);
                                    bool isSystemVerified = CheckUserSystemInfo(username, userHwid, userMacAddress, userProcessorId, userMotherboardId, userLocalIpAddress, userPublicIpAddress, connection);
                                    if (isSystemVerified)
                                    {
                                        bool hasSecurityQuestion = !string.IsNullOrEmpty(GetSecurityQuestion(userID, connection));
                                        bool hasSecurityQuestionAnswer = !string.IsNullOrEmpty(GetSecurityQuestionAnswer(userID, connection));

                                        if (hasSecurityQuestion && hasSecurityQuestionAnswer)
                                        {
                                            Console.WriteLine("System information verified. Login successful!");
                                            Logger logger = new Logger(AppSettings.DbConnectionString);
                                            string logLevel = "Info";
                                            string logDescription = $"User successfully logged in from IP address {userPublicIpAddress}.";
                                            logger.LogTransaction(userID, logLevel, logDescription);
                                            UpdatePassword(username, enteredPassword, connection);
                                            loggedInUsername = username;
                                            return true;
                                        }
                                        else
                                        {
                                            Console.WriteLine("Security question or answer is missing. Please complete your security information.");
                                            if (!hasSecurityQuestion)
                                            {
                                                string randomQuestion = GetRandomSecurityQuestion();
                                                Console.WriteLine($"Answer the following security question:\n{randomQuestion}");
                                                Console.Write("Your answer: ");
                                                string userAnswer = Console.ReadLine();
                                                SaveSecurityQuestion(userID, randomQuestion, connection);
                                                SaveSecurityQuestionAnswer(userID, userAnswer, connection);
                                                Console.WriteLine("Security question and answer saved successfully.");
                                            }
                                            else if (!hasSecurityQuestionAnswer)
                                            {
                                                string securityQuestion = GetSecurityQuestion(userID, connection);

                                                Console.WriteLine($"Security Question: {securityQuestion}");
                                                Console.Write("Enter your security question answer: ");
                                                string userAnswer = Console.ReadLine();
                                                SaveSecurityQuestionAnswer(userID, userAnswer, connection);
                                                Console.WriteLine("Security answer saved successfully.");
                                            }
                                            Console.WriteLine("System information verified. Login successful!");
                                            Logger logger = new Logger(AppSettings.DbConnectionString);
                                            string logLevel = "Info";
                                            string logDescription = $"User successfully logged in from IP address {userPublicIpAddress}.";
                                            logger.LogTransaction(userID, logLevel, logDescription);
                                            UpdatePassword(username, enteredPassword, connection);
                                            loggedInUsername = username;
                                            return true;
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine("System information did not match. Login prohibited!");
                                        if (Properties.Settings.Default.FailedLoginAttempts < 3) Console.WriteLine("Press any key to exit.");
                                        Logger logger = new Logger(AppSettings.DbConnectionString);
                                        string logLevel = "Warning"; //Error', 'Warning', 'Info'
                                        string logDescription = $"Failed login attempt. System information did not match the user.";
                                        logger.LogTransaction(userID, logLevel, logDescription);

                                        Properties.Settings.Default.FailedLoginAttempts++;
                                        Properties.Settings.Default.Save();

                                        if (Properties.Settings.Default.FailedLoginAttempts >= maxFailedAttempts)
                                        {
                                            Console.Write("Do you think your hardware has changed? (yes/no): ");
                                            string response = Console.ReadLine().ToLower();

                                            if (response == "yes")
                                            {
                                                string securityQuestion = GetSecurityQuestion(userID, connection);
                                                string userEnteredAnswer;

                                                if (!string.IsNullOrEmpty(securityQuestion))
                                                {
                                                    Console.WriteLine($"Security Question: {securityQuestion}");
                                                    Console.Write("Your answer: ");
                                                    userEnteredAnswer = Console.ReadLine();
                                                    string correctAnswer = GetSecurityQuestionAnswer(userID, connection);

                                                    if (userEnteredAnswer == correctAnswer)
                                                    {
                                                        Console.WriteLine("Security information verified. Resetting hardware information.");
                                                        Properties.Settings.Default.FailedLoginAttempts = 0;
                                                        Properties.Settings.Default.Save();
                                                        try
                                                        {
                                                            DeleteUserInformationFromDatabase(connection, username);
                                                            UpdateUserHardwareInfo(connection, username, userHwid, userMacAddress, userLocalIpAddress, userPublicIpAddress, userMotherboardId, userProcessorId);
                                                            Console.WriteLine("Hardware information updated successfully.");
                                                            logLevel = "Info"; //Error', 'Warning', 'Info'
                                                            logDescription = $"Hardware information updated successfully.";
                                                            logger.LogTransaction(userID, logLevel, logDescription);
                                                        }
                                                        catch (Exception ex)
                                                        {
                                                            Console.WriteLine($"An error occurred while updating hardware information: {ex.Message}");
                                                            Console.WriteLine("Please contact the software developer for assistance.");
                                                            try
                                                            {
                                                                logLevel = "Error"; // 'Error', 'Warning', 'Info'
                                                                logDescription = $"An error occurred in Hardware information updated: {ex.Message}";
                                                                logger.LogTransaction(userID, logLevel, logDescription);
                                                            }
                                                            catch (Exception logEx)
                                                            {
                                                                FileLogger loggerFile = new FileLogger("Logs.log");
                                                                loggerFile.LogError($"An error occurred in Hardware information updated: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                                                            }
                                                        }

                                                    }
                                                    else
                                                    {
                                                        Console.WriteLine("Security information did not match. Aborting hardware reset.");
                                                        userPublicIpAddress = GetPublicIpAddress();
                                                        FileLogger loggerFile = new FileLogger("Logs.log");
                                                        loggerFile.LogError($"Security information did not match. Aborting hardware reset. User IP: {userPublicIpAddress}", "WARNING");
                                                    }
                                                }
                                                else
                                                {
                                                    Console.WriteLine("No security question found. Aborting hardware reset.");
                                                    userPublicIpAddress = GetPublicIpAddress();
                                                    FileLogger loggerFile = new FileLogger("Logs.log");
                                                    loggerFile.LogError($"No security question found. Aborting hardware reset. User IP: {userPublicIpAddress}", "WARNING");
                                                }
                                            }
                                            else
                                            {
                                                Console.WriteLine("Operation canceled. No action will be taken.");
                                                Console.WriteLine("Press any key to exit.");
                                                Console.ReadKey(); 
                                                Properties.Settings.Default.FailedLoginAttempts = 0;
                                                Properties.Settings.Default.Save();
                                            }
                                        }
                                        Console.ReadKey();
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("Invalid password!");
                                    Console.WriteLine("Press any key to exit.");
                                    Console.ReadKey();
                                }
                            }
                            else
                            {
                                Console.WriteLine("User not found.");
                                Console.WriteLine("Press any key to exit.");
                                Console.ReadKey();
                            }
                            connection.Close();
                        }
                        return false;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("An error occurred in Login: " + ex.Message);
                    Console.WriteLine("Please contact the software developer for assistance.");
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in Login: {ex.Message}. User IP: {userPublicIpAddress}", "ERROR");

                    Console.WriteLine("Press any key to exit.");
                    Console.ReadKey();
                }
            } while (true);
        }
        static int GetUserId(SqlConnection connection, string username)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                string queryUsers = "SELECT UserID FROM Users WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(queryUsers, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    object result = command.ExecuteScalar();

                    return result != null ? (int)result : -1;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in GetUserId: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in GetUserId: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in GetUserId: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                return -1;
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        private static bool CheckUserSystemInfo(string username, string hwid, string macAddress, string processorId, string motherboardId, string userLocalIpAddress, string userPublicIpAddress, SqlConnection connection)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                string query = "SELECT Username FROM Users WHERE Username = @Username AND HardwareID = @HardwareID AND MacAddress = @MacAddress AND ProcessorID = @ProcessorID AND MotherboardID = @MotherboardID AND LocalIP = @LocalIP AND PublicIP = @PublicIP";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@HardwareID", hwid);
                    command.Parameters.AddWithValue("@MacAddress", macAddress);
                    command.Parameters.AddWithValue("@ProcessorID", processorId);
                    command.Parameters.AddWithValue("@MotherboardID", motherboardId);
                    command.Parameters.AddWithValue("@LocalIP", userLocalIpAddress);
                    command.Parameters.AddWithValue("@PublicIP", userPublicIpAddress);

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in CheckUserSystemInfo: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int logUserID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error";
                    string logDescription = $"An error occurred in CheckUserSystemInfo: {ex.Message}";
                    logger.LogTransaction(logUserID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in CheckUserSystemInfo: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }

                return false;
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        static void UpdateIpAddress(string username, string localIpAddress, string publicIpAddress, SqlConnection connection)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                string query = "UPDATE Users SET LocalIP = @LocalIP, PublicIP = @PublicIP WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@LocalIP", localIpAddress);
                    command.Parameters.AddWithValue("@PublicIP", publicIpAddress);

                    int rowsAffected = command.ExecuteNonQuery();

                    if (rowsAffected > 0)
                    {
                        Console.WriteLine($"IP addresses updated successfully for user: {username}");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Info"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"IP addresses updated successfully for user: {username}";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                    else
                    {
                        Console.WriteLine($"No rows were updated for user: {username}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in UpdateIpAddress: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in UpdateIpAddress: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in UpdateIpAddress: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();

            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        static string GetStoredPassword(string username, SqlConnection connection)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                string query = "SELECT Password FROM Users WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);

                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            return reader["Password"].ToString();
                        }
                        else
                        {
                            Console.WriteLine($"Password not found for user: {username}");
                            return null;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in GetStoredPassword: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in GetStoredPassword: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in GetStoredPassword: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                return null;
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        static bool CheckPassword(string enteredPassword, string storedPassword)
        {
            try
            {
                if (storedPassword.Length == 64)
                {
                    string enteredHashedPassword = HashPassword(enteredPassword);
                    return enteredHashedPassword == storedPassword;
                }
                else
                {
                    return enteredPassword == storedPassword;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in CheckPassword: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");
                string userPublicIpAddress = GetPublicIpAddress();
                FileLogger logger = new FileLogger("Logs.log");
                logger.LogError($"An error occurred in CheckPassword: {ex.Message} User IP: {userPublicIpAddress}", "ERROR");
                return false;
            }
        }
        static void UpdatePassword(string username, string newPassword, SqlConnection connection)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();
                string hashedPassword = HashPassword(newPassword);
                string query = "UPDATE Users SET Password = @Password WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@Password", hashedPassword);

                    command.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in UpdatePassword: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in UpdatePassword: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in UpdatePassword: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();

            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        static void DeleteUserInformationFromDatabase(SqlConnection connection, string username)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();
                string usersQuery = "UPDATE Users SET HardwareID = NULL, MacAddress = NULL, LocalIP = NULL, PublicIP = NULL, MotherboardID = NULL, ProcessorID = NULL WHERE Username = @Username";

                using (SqlCommand usersCommand = new SqlCommand(usersQuery, connection))
                {
                    usersCommand.Parameters.AddWithValue("@Username", username);
                    usersCommand.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in DeleteUserInformationFromDatabase: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in DeleteUserInformationFromDatabase: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in DeleteUserInformationFromDatabase: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        static void UpdateUserHardwareInfo(SqlConnection connection, string username, string newHwid, string newMacAddress, string newLocalIP, string newPublicIP, string newMotherboardID, string newProcessorID)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                string existingHardwareInfoQuery = "SELECT HardwareID, MacAddress, LocalIP, PublicIP, MotherboardID, ProcessorID FROM Users WHERE Username = @Username";
                string existingHwid = "", existingMacAddress = "", existingLocalIP = "", existingPublicIP = "", existingMotherboardID = "", existingProcessorID = "";

                using (SqlCommand command = new SqlCommand(existingHardwareInfoQuery, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            existingHwid = reader["HardwareID"].ToString();
                            existingMacAddress = reader["MacAddress"].ToString();
                            existingLocalIP = reader["LocalIP"].ToString();
                            existingPublicIP = reader["PublicIP"].ToString();
                            existingMotherboardID = reader["MotherboardID"].ToString();
                            existingProcessorID = reader["ProcessorID"].ToString();
                        }
                        else
                        {
                            Console.WriteLine("User not found in the database.");
                            return;
                        }
                    }
                }
                bool allParamsAreEmpty = string.IsNullOrEmpty(existingHwid) &&
                                         string.IsNullOrEmpty(existingMacAddress) &&
                                         string.IsNullOrEmpty(existingLocalIP) &&
                                         string.IsNullOrEmpty(existingPublicIP) &&
                                         string.IsNullOrEmpty(existingMotherboardID) &&
                                         string.IsNullOrEmpty(existingProcessorID);

                if (allParamsAreEmpty)
                {
                    string query = "UPDATE Users SET ";
                    List<string> updateStatements = new List<string>();

                    if (!string.IsNullOrEmpty(newHwid))
                        updateStatements.Add("HardwareID = @Hwid");
                    if (!string.IsNullOrEmpty(newMacAddress))
                        updateStatements.Add("MacAddress = @MacAddress");
                    if (!string.IsNullOrEmpty(newLocalIP))
                        updateStatements.Add("LocalIP = @LocalIP");
                    if (!string.IsNullOrEmpty(newPublicIP))
                        updateStatements.Add("PublicIP = @PublicIP");
                    if (!string.IsNullOrEmpty(newMotherboardID))
                        updateStatements.Add("MotherboardID = @MotherboardID");
                    if (!string.IsNullOrEmpty(newProcessorID))
                        updateStatements.Add("ProcessorID = @ProcessorID");

                    query += string.Join(", ", updateStatements);
                    query += " WHERE Username = @Username";

                    using (SqlCommand command = new SqlCommand(query, connection))
                    {
                        command.Parameters.AddWithValue("@Username", username);
                        if (!string.IsNullOrEmpty(newHwid))
                            command.Parameters.AddWithValue("@Hwid", newHwid);
                        if (!string.IsNullOrEmpty(newMacAddress))
                            command.Parameters.AddWithValue("@MacAddress", newMacAddress);
                        if (!string.IsNullOrEmpty(newLocalIP))
                            command.Parameters.AddWithValue("@LocalIP", newLocalIP);
                        if (!string.IsNullOrEmpty(newPublicIP))
                            command.Parameters.AddWithValue("@PublicIP", newPublicIP);
                        if (!string.IsNullOrEmpty(newMotherboardID))
                            command.Parameters.AddWithValue("@MotherboardID", newMotherboardID);
                        if (!string.IsNullOrEmpty(newProcessorID))
                            command.Parameters.AddWithValue("@ProcessorID", newProcessorID);

                        command.ExecuteNonQuery();

                        Console.WriteLine("Users hardware information updated successfully.");
                    }
                }
                else
                {
                    Console.WriteLine("No information provided for update.");
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"No information provided for update.";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in UpdateUserHardwareInfo: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int logUserID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error";
                    string logDescription = $"An error occurred in UpdateUserHardwareInfo: {ex.Message}";
                    logger.LogTransaction(logUserID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in UpdateUserHardwareInfo: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }

                Console.ReadKey();
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }

        private static string GetSecurityQuestion(int userID, SqlConnection connection)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();
                string query = "SELECT SecurityQuestion FROM Users WHERE UserID = @UserID";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@UserID", userID);
                    return command.ExecuteScalar()?.ToString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in GetSecurityQuestion: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int logUserID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error";
                    string logDescription = $"An error occurred in GetSecurityQuestion: {ex.Message}";
                    logger.LogTransaction(logUserID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in GetSecurityQuestion: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
                return null;
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        private static string GetSecurityQuestionAnswer(int userID, SqlConnection connection)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();
                string query = "SELECT SecurityQuestionAnswer FROM Users WHERE UserID = @UserID";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@UserID", userID);
                    return command.ExecuteScalar()?.ToString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in GetSecurityQuestionAnswer: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int logUserID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error";
                    string logDescription = $"An error occurred in GetSecurityQuestionAnswer: {ex.Message}";
                    logger.LogTransaction(logUserID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in GetSecurityQuestionAnswer: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
                return null;
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        private static void SaveSecurityQuestion(int userID, string question, SqlConnection connection)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();
                string query = "UPDATE Users SET SecurityQuestion = @Question WHERE UserID = @UserID";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Question", question);
                    command.Parameters.AddWithValue("@UserID", userID);
                    command.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in GetSecurityQuestionAnswer: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int logUserID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error";
                    string logDescription = $"An error occurred in GetSecurityQuestionAnswer: {ex.Message}";
                    logger.LogTransaction(logUserID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in GetSecurityQuestionAnswer: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }

        }
        private static void SaveSecurityQuestionAnswer(int userID, string answer, SqlConnection connection)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();
                string query = "UPDATE Users SET SecurityQuestionAnswer = @Answer WHERE UserID = @UserID";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Answer", answer);
                    command.Parameters.AddWithValue("@UserID", userID);
                    command.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in GetSecurityQuestionAnswer: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int logUserID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error";
                    string logDescription = $"An error occurred in GetSecurityQuestionAnswer: {ex.Message}";
                    logger.LogTransaction(logUserID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in GetSecurityQuestionAnswer: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        static string GetRandomSecurityQuestion()
        {
            List<string> securityQuestions = new List<string>
    {
        "What is the name of your first pet?",
        "In which city were you born?",
        "What is the name of your favorite childhood friend?",
        "In which year did you graduate from high school?",
        "What is the model of your first car?",
        "Where did you spend your honeymoon?",
        "What is the name of your favorite teacher?",
        "What is your favorite movie?",
        "In which city did you meet your spouse?",
        "What is the name of the street you grew up on?",
        "What is the make of your first computer?",
        "What is the name of your maternal grandmother?"
        };
            Random random = new Random();
            int index = random.Next(securityQuestions.Count);

            return securityQuestions[index];
        }
        static void UserMenu(SqlConnection connection)
        {
            try
            {
                string choice;
                do
                {
                   // Console.Clear();
                    Console.Title = "Zyix Auth System - User Menu";
                    Console.WriteLine("User Menu:");
                    Console.WriteLine("1. Update User Information");
                    Console.WriteLine("2. Manage User License");
                    Console.WriteLine("3. Switch to Application");
                    Console.WriteLine("4. Exit");

                    Console.Write("Enter your choice: ");
                    choice = Console.ReadLine();
                    switch (choice)
                    {
                        case "1":
                            ManageUserInformation(connection);
                            break;
                        case "2":
                            ManageUserLicense(connection);
                            break;
                        case "3":
                            HandleMenu(connection);
                            break;
                        case "4":
                            Console.WriteLine("Exiting the application...");
                            Thread.Sleep(500);
                            Environment.Exit(0);
                            break;
                        default:
                            Console.WriteLine("Invalid choice. Press any key to try again.");
                            Console.ReadKey();
                            break;
                    }
                } while (choice != "4");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in User Menu: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in User Menu: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in User Menu: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }
        static void ManageUserInformation(SqlConnection connection)
        {
            try
            {
                string choice;
                do
                {
                    Console.Clear();
                    Console.Title = "Zyix Auth System - User Information Menu";
                    Console.WriteLine("User Information Menu:");
                    Console.WriteLine("1. Update Username");
                    Console.WriteLine("2. Update Password");
                    Console.WriteLine("3. Update Email Address");
                    Console.WriteLine("4. Back to Main Menu");

                    Console.Write("Enter your choice: ");
                    choice = Console.ReadLine();
                    switch (choice)
                    {
                        case "1":
                            UpdateUsername(connection, loggedInUsername);
                            break;
                        case "2":
                            UpdatePassword(connection, loggedInUsername);
                            break;
                        case "3":
                            UpdateEmailAddress(connection, loggedInUsername);
                            break;
                        case "4":
                            return;
                        default:
                            Console.WriteLine("Invalid choice. Press any key to try again.");
                            Console.ReadKey();
                            break;
                    }
                } while (choice != "4");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in Manage User Information: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in Manage User Information: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in Manage User Information: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }
        // UpdateUsername
        static void UpdateUsername(SqlConnection connection, string loggedInUsername)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                Console.Clear();
                string query = "SELECT Username FROM Users WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", loggedInUsername);

                    object result = command.ExecuteScalar();

                    if (result != null)
                    {
                        string currentUsername = result.ToString();

                        Console.Write($"Your current username: {currentUsername}");
                        Console.WriteLine();
                        Console.Write("Enter your new username: ");
                        string newUsername = Console.ReadLine();
                        if (string.IsNullOrWhiteSpace(newUsername))
                        {
                            Console.WriteLine("Username cannot be empty. Please try again.");
                            Console.WriteLine("Press any key to return to the User Information Menu.");
                            Console.ReadKey();
                            return;
                        }
                        if (!IsValidUsername(newUsername))
                        {
                            Console.WriteLine("Invalid username. Username cannot contain special characters.");
                            Console.WriteLine("Press any key to return to the User Information Menu.");
                            Console.ReadKey();
                            return;
                        }

                        query = "SELECT COUNT(*) FROM Users WHERE Username = @NewUsername";

                        using (SqlCommand checkCommand = new SqlCommand(query, connection))
                        {
                            checkCommand.Parameters.AddWithValue("@NewUsername", newUsername);

                            int userCount = (int)checkCommand.ExecuteScalar();

                            if (userCount > 0)
                            {
                                Console.WriteLine($"Username '{newUsername}' is already taken. Please choose another username.");
                            }
                            else
                            {
                                string updateQuery = "UPDATE Users SET Username = @NewUsername WHERE Username = @CurrentUsername";

                                using (SqlCommand updateCommand = new SqlCommand(updateQuery, connection))
                                {
                                    updateCommand.Parameters.AddWithValue("@NewUsername", newUsername);
                                    updateCommand.Parameters.AddWithValue("@CurrentUsername", currentUsername);

                                    int rowsAffected = updateCommand.ExecuteNonQuery();

                                    if (rowsAffected > 0)
                                    {
                                        Console.WriteLine($"Username updated successfully from '{currentUsername}' to '{newUsername}'.");
                                        int userID = GetUserId(connection, loggedInUsername);
                                        Logger logger = new Logger(AppSettings.DbConnectionString);
                                        string logLevel = "Info"; // 'Error', 'Warning', 'Info'
                                        string logDescription = $"Username updated successfully from '{currentUsername}' to '{newUsername}'.";
                                        logger.LogTransaction(userID, logLevel, logDescription);
                                        Console.WriteLine("Please log in again for the changes to take effect.");
                                        Console.WriteLine("Press any key to return to the login screen.");
                                        Console.ReadKey();
                                        Main();
                                    }
                                    else
                                    {
                                        Console.WriteLine($"No user found with the username '{currentUsername}'. Username was not updated.");
                                        int userID = GetUserId(connection, loggedInUsername);
                                        Logger logger = new Logger(AppSettings.DbConnectionString);
                                        string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                                        string logDescription = $"No user found with the username '{currentUsername}'. Username was not updated.";
                                        logger.LogTransaction(userID, logLevel, logDescription);
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine($"No user found with the username '{loggedInUsername}'. Username was not updated.");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"No user found with the username '{loggedInUsername}'. Username was not updated.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in Updating Username: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in Updating Username: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in Updating Username: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }

            Console.WriteLine("Press any key to return to the User Information Menu.");
            Console.ReadKey();
        }
        static bool IsValidUsername(string username)
        {
            string pattern = "^[a-zA-Z0-9_]*$";
            return Regex.IsMatch(username, pattern);
        }
        // UpdateUsername

        // UpdatePassword
        static void UpdatePassword(SqlConnection connection, string loggedInUsername)
        {
            try
            {
                string newPassword;
                Console.Clear();

                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                Console.Write("Enter your new password: ");
                ConsoleKeyInfo key = Console.ReadKey(true);
                newPassword = "";

                while (key.Key != ConsoleKey.Enter)
                {
                    if (key.Key != ConsoleKey.Backspace)
                    {
                        newPassword += key.KeyChar;
                        Console.Write("*");
                    }
                    else if (newPassword.Length > 0)
                    {
                        newPassword = newPassword.Substring(0, newPassword.Length - 1);
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                        Console.Write(" ");
                        Console.SetCursorPosition(Console.CursorLeft - 1, Console.CursorTop);
                    }

                    key = Console.ReadKey(true);
                }
                Console.WriteLine();
                if (string.IsNullOrWhiteSpace(newPassword))
                {
                    Console.WriteLine("Password cannot be empty. Please try again.");
                    Console.WriteLine("Press any key to return to the User Information Menu.");
                    Console.ReadKey();
                    return;
                }
                string hashedPassword = HashPassword(newPassword);

                string query = "UPDATE Users SET Password = @Password WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Password", hashedPassword);
                    command.Parameters.AddWithValue("@Username", loggedInUsername);

                    int rowsAffected = command.ExecuteNonQuery();

                    if (rowsAffected > 0)
                    {
                        Console.WriteLine("Password updated successfully.");
                        Console.WriteLine("Please log in again with your new password.");
                        Console.WriteLine("Press any key to return to the login screen.");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Info"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"Password updated successfully.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                        Console.ReadKey();
                        Main();
                    }
                    else
                    {
                        Console.WriteLine($"No user found with the username '{loggedInUsername}'. Password was not updated.");
                        Console.WriteLine("Press any key to return to the User Information Menu.");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"No user found with the username '{loggedInUsername}'. Password was not updated.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                        Console.ReadKey();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in Updating Password: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in Updating Password: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in Updating Password: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
            Console.WriteLine("Press any key to return to the User Information Menu.");
            Console.ReadKey();
        }
        // UpdatePassword

        // UpdateEmailAddress
        static void UpdateEmailAddress(SqlConnection connection, string loggedInUsername)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();
                Console.Clear();

                string queryCurrentEmail = "SELECT Email FROM Users WHERE Username = @Username";
                string currentEmailAddress;
                using (SqlCommand currentEmailCommand = new SqlCommand(queryCurrentEmail, connection))
                {
                    currentEmailCommand.Parameters.AddWithValue("@Username", loggedInUsername);
                    currentEmailAddress = (string)currentEmailCommand.ExecuteScalar();
                }

                Console.WriteLine($"Your current email address: {currentEmailAddress}");

                Console.Write("Enter your new email address: ");
                string newEmailAddress = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(newEmailAddress) || !IsValidEmail(newEmailAddress))
                {
                    Console.WriteLine("Invalid email address. Please enter a valid email address.");
                    Console.WriteLine("Press any key to return to the User Information Menu.");
                    Console.ReadKey();
                    return;
                }

                string query = "SELECT COUNT(*) FROM Users WHERE Email = @Email";
                using (SqlCommand checkCommand = new SqlCommand(query, connection))
                {
                    checkCommand.Parameters.AddWithValue("@Email", newEmailAddress);
                    int userCount = (int)checkCommand.ExecuteScalar();

                    if (userCount > 0)
                    {
                        Console.WriteLine($"EmailAdress '{newEmailAddress}' is already taken. Please choose another email address.");
                        Console.WriteLine("Press any key to return to the User Information Menu.");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"EmailAdress '{newEmailAddress}' is already taken. Please choose another email address.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                        Console.ReadKey();
                        return;
                    }
                }
                query = "UPDATE Users SET Email = @Email WHERE Username = @Username";
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Email", newEmailAddress);
                    command.Parameters.AddWithValue("@Username", loggedInUsername);

                    int rowsAffected = command.ExecuteNonQuery();

                    if (rowsAffected > 0)
                    {
                        Console.WriteLine("Email address updated successfully.");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Info"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"Email address updated successfully.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                    else
                    {
                        Console.WriteLine($"No user found with the username '{loggedInUsername}'. Email address was not updated.");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"No user found with the username '{loggedInUsername}'. Email address was not updated.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in updating Email Address: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in Email Address: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in Email Address: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }

            Console.WriteLine("Press any key to return to the User Information Menu.");
            Console.ReadKey();
        }
        // UpdateEmailAddress
        static bool IsValidEmail(string email)
        {
            string pattern = @"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$";
            Regex regex = new Regex(pattern);
            return regex.IsMatch(email);
        }
        static void ManageUserLicense(SqlConnection connection)
        {
            try
            {
                string choice;
                do
                {
                    Console.Clear();
                    Console.Title = "Zyix Auth System - License Management Menu";
                    Console.WriteLine("License Management Menu:");
                    Console.WriteLine("1. Enter New License Key");
                    Console.WriteLine("2. Check License Expiry Date");
                    Console.WriteLine("3. Change License Key");
                    Console.WriteLine("4. Back to Main Menu");

                    Console.Write("Enter your choice: ");
                    choice = Console.ReadLine();

                    switch (choice)
                    {
                        case "1":
                            EnterNewLicenseKey(connection);
                            break;
                        case "2":
                            CheckLicenseExpiryDate(connection);
                            break;
                        case "3":
                            ChangeLicenseKey(connection);
                            break;
                        case "4":
                            return;
                        default:
                            Console.WriteLine("Invalid choice. Please try again.");
                            break;
                    }
                } while (choice != "4");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in License Management Menu: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in License Management Menu: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in License Management Menu: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }
        static void EnterNewLicenseKey(SqlConnection connection)
        {
            try
            {
                Console.Clear();
                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                Console.Write("Enter license key: ");
                string licenseKey = Console.ReadLine();

                licenseKey = EncryptLicenseKey(licenseKey);

                if (CheckLicenseKey(connection, licenseKey))
                {
                    if (!IsLicenseKeyUsed(connection, licenseKey))
                    {
                        int userID = GetUserId(connection, loggedInUsername);
                        ActivateLicense(connection, licenseKey, userID);
                    }
                    else
                    {
                        Console.WriteLine("Invalid license key!");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"Invalid license key!";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                }
                else
                {
                    Console.WriteLine("Invalid license key!");
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"Invalid license key!";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in Enter New LicenseKey: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in Enter New LicenseKey: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in Enter New LicenseKey: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
            Console.WriteLine("Press any key to return to the License Management Menu");
            Console.ReadKey();
        }
        static bool CheckLicenseKey(SqlConnection connection, string licenseKey)
        {
            try
            {
                string query = "SELECT COUNT(*) FROM Licenses WHERE LicenseKey = @LicenseKey";
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@LicenseKey", licenseKey);
                if (connection.State == ConnectionState.Closed)
                    connection.Open();
                int count = (int)command.ExecuteScalar();
                return count > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while Checking The License Key: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while Checking The License Key: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while Checking The License Key: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
                return false;
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        static bool IsLicenseKeyUsed(SqlConnection connection, string licenseKey)
        {
            try
            {
                string query = "SELECT IsActive FROM Licenses WHERE LicenseKey = @LicenseKey AND (UserID IS NOT NULL OR IsActive = @IsActive)";
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@LicenseKey", licenseKey);
                command.Parameters.AddWithValue("@IsActive", true);

                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                using (SqlDataReader reader = command.ExecuteReader())
                {
                    bool isUsed = reader.HasRows;
                    return isUsed;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while Checking if The License Key is Used: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while Checking if The License Key is Used: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while Checking if The License Key is Used: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
                return false;
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        static void ActivateLicense(SqlConnection connection, string licenseKey, int userId)
        {
            try
            {
                string query = "UPDATE Licenses SET IsActive = @IsActive, UserID = @UserID WHERE LicenseKey = @LicenseKey";
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@LicenseKey", licenseKey);
                command.Parameters.AddWithValue("@UserID", userId);
                command.Parameters.AddWithValue("@IsActive", true);

                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                int rowsAffected = command.ExecuteNonQuery();

                if (rowsAffected > 0)
                {
                    string queryUpdateUserLicense = "UPDATE Users SET LicenseKey = @LicenseKey WHERE UserID = @UserID";
                    SqlCommand commandUpdateUserLicense = new SqlCommand(queryUpdateUserLicense, connection);
                    commandUpdateUserLicense.Parameters.AddWithValue("@LicenseKey", licenseKey);
                    commandUpdateUserLicense.Parameters.AddWithValue("@UserID", userId);

                    int userRowsAffected = commandUpdateUserLicense.ExecuteNonQuery();

                    if (userRowsAffected > 0)
                    {
                        Console.WriteLine("License activated successfully!");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Info"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"License activated successfully!";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                    else
                    {
                        Console.WriteLine("Failed to update user license.");
                        Console.WriteLine("Please contact the software developer for assistance.");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"Failed to update user license.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                }
                else
                {
                    Console.WriteLine("Failed to activate license.");
                    Console.WriteLine("Please contact the software developer for assistance.");
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"Failed to activate license.";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while Activating The License: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while Activating The License: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while Activating The License: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        static void CheckLicenseExpiryDate(SqlConnection connection)
        {
            try
            {
                int loggedInUserId = GetUserId(connection, loggedInUsername);
                string query = "SELECT ExpirationDate FROM Licenses WHERE UserID = @UserID AND IsActive = @IsActive";
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@UserID", loggedInUserId);
                command.Parameters.AddWithValue("@IsActive", true);

                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                using (SqlDataReader reader = command.ExecuteReader())
                {
                    if (reader.Read())
                    {
                        DateTime expirationDate = Convert.ToDateTime(reader["ExpirationDate"]);
                        TimeSpan remainingTime = expirationDate - DateTime.Now;

                        if (remainingTime.TotalDays > 0)
                        {
                            int remainingYears = (int)(remainingTime.TotalDays / 365);
                            int remainingMonths = (int)((remainingTime.TotalDays % 365) / 30);
                            int remainingDays = (int)(remainingTime.TotalDays % 30);
                            int remainingHours = (int)(remainingTime.TotalHours % 24);
                            int remainingMinutes = (int)(remainingTime.TotalMinutes % 60);
                            int remainingSeconds = (int)(remainingTime.TotalSeconds % 60);

                            string remainingTimeString = "";

                            if (remainingYears > 0)
                            {
                                remainingTimeString += $"{remainingYears} years, ";
                            }

                            if (remainingMonths > 0)
                            {
                                remainingTimeString += $"{remainingMonths} months, ";
                            }

                            if (remainingDays > 0)
                            {
                                remainingTimeString += $"{remainingDays} days, ";
                            }
                            remainingTimeString += $"{remainingHours} hours, {remainingMinutes} minutes and {remainingSeconds} seconds.";
                            Console.Clear();
                            Console.WriteLine($"License expires in {remainingTimeString}");
                            Logger logger = new Logger(AppSettings.DbConnectionString);
                            string logLevel = "Info"; // 'Error', 'Warning', 'Info'
                            string logDescription = $"User checked license expiry date";
                            logger.LogTransaction(loggedInUserId, logLevel, logDescription);
                        }
                        else
                        {
                            Console.WriteLine("License has expired.");
                            Logger logger = new Logger(AppSettings.DbConnectionString);
                            string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                            string logDescription = $"License has expired.";
                            logger.LogTransaction(loggedInUserId, logLevel, logDescription);
                        }
                    }
                    else
                    {
                        Console.WriteLine("You don't have a defined license.");
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"You don't have a defined license.";
                        logger.LogTransaction(loggedInUserId, logLevel, logDescription);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while checking the license expiry date: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while checking the license expiry date: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while checking the license expiry date: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
            Console.WriteLine("Press any key to return to the License Management Menu");
            Console.ReadKey();
        }
        static void ChangeLicenseKey(SqlConnection connection)
        {
            Console.Clear();
            try
            {
                if (!IsLicenseDefined(connection))
                {
                    Console.WriteLine("You don't have a defined license.");
                    Console.WriteLine("Press any key to return to the License Management Menu");
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"You don't have a defined license.";
                    logger.LogTransaction(userID, logLevel, logDescription);
                    Console.ReadKey();
                    return;
                }
                bool isLicenseActive = IsLicenseActive(connection);
                bool isLicenseExpired = IsLicenseExpired(connection);
                if (!isLicenseActive || isLicenseExpired)
                {
                    Console.Write("Enter your new license key: ");
                    string newLicenseKey = Console.ReadLine();
                    newLicenseKey = EncryptLicenseKey(newLicenseKey);

                    if (IsNewLicenseKeyValid(connection, newLicenseKey))
                        UpdateLicenseKey(connection, newLicenseKey);
                    else
                    {
                        Console.WriteLine("The entered license key is not valid.");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"The entered license key is not valid.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }  
                }
                else
                {
                    Console.WriteLine("Your license is currently active and valid. You cannot change your license key.");
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Warning"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"Your license is currently active and valid. You cannot change your license key.";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while changing the license key: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while changing the license key: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while changing the license key: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
            Console.WriteLine("Press any key to return to the License Management Menu");
            Console.ReadKey();
        }

        static bool IsNewLicenseKeyValid(SqlConnection connection, string newLicenseKey)
        {
            try
            {
                string query = "SELECT COUNT(*) FROM Licenses WHERE LicenseKey = @LicenseKey AND IsActive = 0 AND UserID IS NULL";
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@LicenseKey", newLicenseKey);

                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                int count = (int)command.ExecuteScalar();

                return count > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while checking the validity of the new license key: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while checking the validity of the new license key: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while checking the validity of the new license key: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
                return false;
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }

        static bool IsLicenseDefined(SqlConnection connection)
        {
            try
            {
                int loggedInUserId = GetUserId(connection, loggedInUsername);
                string query = "SELECT COUNT(*) FROM Licenses WHERE UserID = @UserID AND LicenseKey IN (SELECT LicenseKey FROM Users WHERE UserID = @UserID AND LicenseKey IS NOT NULL)";
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@UserID", loggedInUserId);
                if (connection.State == ConnectionState.Closed)
                    connection.Open();
                int licenseCount = (int)command.ExecuteScalar();
                return licenseCount > 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while checking license definition status: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while checking license definition status: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while checking license definition status: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
                return false;
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }

        static bool IsLicenseActive(SqlConnection connection)
        {
            try
            {
                int loggedInUserId = GetUserId(connection, loggedInUsername);
                string query = "SELECT IsActive FROM Licenses WHERE UserID = @UserID AND IsActive = 1";
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@UserID", loggedInUserId);

                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                object result = command.ExecuteScalar();
                bool isActive = result != null && (bool)result;

                return isActive;
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while checking license activation status: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while checking license activation status: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while checking license activation status: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
                return false;
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }

        static bool IsLicenseExpired(SqlConnection connection)
        {
            try
            {
                int loggedInUserId = GetUserId(connection, loggedInUsername);
                string query = "SELECT ExpirationDate FROM Licenses WHERE UserID = @UserID AND IsActive = @IsActive";
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@UserID", loggedInUserId);
                command.Parameters.AddWithValue("@IsActive", true);

                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                DateTime expirationDate = Convert.ToDateTime(command.ExecuteScalar());
                bool isExpired = expirationDate < DateTime.Now;

                return isExpired;
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while checking license expiry status: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while checking license expiry status: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while checking license expiry status: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
                return false;
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        static string GetLoggedInUserLicenseKey(SqlConnection connection, string loggedInUsername)
        {
            try
            {
                string query = "SELECT LicenseKey FROM Licenses WHERE UserID = (SELECT UserID FROM Users WHERE Username = @Username)";
                SqlCommand command = new SqlCommand(query, connection);
                command.Parameters.AddWithValue("@Username", loggedInUsername);

                if (connection.State == ConnectionState.Closed)
                    connection.Open();
                string licenseKey = command.ExecuteScalar()?.ToString();

                return licenseKey;
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while fetching the logged-in user's license key: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");
                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while fetching the logged-in user's license key: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while fetching the logged-in user's license key: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
                return null;
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        static void UpdateLicenseKey(SqlConnection connection, string newLicenseKey)
        {
            try
            {
                string loggedInLicenseKey = GetLoggedInUserLicenseKey(connection, loggedInUsername);
                int loggedInUserId = GetUserId(connection, loggedInUsername);

                if (!string.IsNullOrEmpty(loggedInLicenseKey))
                {
                    string queryDisableOldLicense = "UPDATE Licenses SET UserID = NULL, IsActive = 'False' WHERE LicenseKey = @OldLicenseKey";
                    SqlCommand commandDisableOldLicense = new SqlCommand(queryDisableOldLicense, connection);
                    commandDisableOldLicense.Parameters.AddWithValue("@OldLicenseKey", loggedInLicenseKey);

                    if (connection.State == ConnectionState.Closed)
                        connection.Open();

                    int rowsAffected = commandDisableOldLicense.ExecuteNonQuery();

                    if (rowsAffected > 0)
                    {
                        string queryUpdateNewLicense = "UPDATE Licenses SET UserID = @UserID, IsActive = @IsActive WHERE LicenseKey = @NewLicenseKey";
                        SqlCommand commandUpdateNewLicense = new SqlCommand(queryUpdateNewLicense, connection);
                        commandUpdateNewLicense.Parameters.AddWithValue("@NewLicenseKey", newLicenseKey);
                        commandUpdateNewLicense.Parameters.AddWithValue("@UserID", loggedInUserId);
                        commandUpdateNewLicense.Parameters.AddWithValue("@IsActive", true);

                        rowsAffected = commandUpdateNewLicense.ExecuteNonQuery();

                        if (rowsAffected > 0)
                        {
                            string queryUpdateUserLicense = "UPDATE Users SET LicenseKey = @LicenseKey WHERE UserID = @UserID";
                            SqlCommand commandUpdateUserLicense = new SqlCommand(queryUpdateUserLicense, connection);
                            commandUpdateUserLicense.Parameters.AddWithValue("@LicenseKey", newLicenseKey);
                            commandUpdateUserLicense.Parameters.AddWithValue("@UserID", loggedInUserId);

                            int userRowsAffected = commandUpdateUserLicense.ExecuteNonQuery();
                            if (userRowsAffected > 0 )
                            {
                                Console.WriteLine("License key has been updated successfully.");
                                int userID = GetUserId(connection, loggedInUsername);
                                Logger logger = new Logger(AppSettings.DbConnectionString);
                                string logLevel = "Info"; // 'Error', 'Warning', 'Info'
                                string logDescription = $"License key has been updated successfully.";
                                logger.LogTransaction(userID, logLevel, logDescription);
                            }
                            else
                            {
                                Console.WriteLine("Failed to update user license.");
                                Console.WriteLine("Please contact the software developer for assistance.");
                                int userID = GetUserId(connection, loggedInUsername);
                                Logger logger = new Logger(AppSettings.DbConnectionString);
                                string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                                string logDescription = $"Failed to update user license.";
                                logger.LogTransaction(userID, logLevel, logDescription);
                            }
                        }
                        else
                        {
                            Console.WriteLine("Failed to update the license key. Please make sure you entered a valid license key.");
                            Console.WriteLine("Please contact the software developer for assistance.");
                            int userID = GetUserId(connection, loggedInUsername);
                            Logger logger = new Logger(AppSettings.DbConnectionString);
                            string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                            string logDescription = $"Failed to update the license key. Please make sure you entered a valid license key.";
                            logger.LogTransaction(userID, logLevel, logDescription);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Failed to disable the old license key.");
                        Console.WriteLine("Please contact the software developer for assistance.");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"Failed to disable the old license key.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                }
                else
                {
                    Console.WriteLine("Failed to fetch the logged-in user's license key.");
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"Failed to fetch the logged-in user's license key.";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred while updating the license key: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while updating the license key: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while updating the license key: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            finally
            {
                if (connection.State == ConnectionState.Open)
                    connection.Close();
            }
        }
        static void HandleMenu(SqlConnection connection)
        {
            try
            {
                string choice;
                do
                {
                    Console.Clear();
                    Console.Title = "Zyix Auth System - Application";
                    Console.WriteLine("Application:");
                    Console.WriteLine("1. Switch to the application");
                    Console.WriteLine("2. Back to Main Menu");
                    Console.Write("Enter your choice: ");
                    choice = Console.ReadLine();

                    switch (choice)
                    {
                        case "1":
                            SwitchToApplication(connection);
                            break;
                        case "2":
                            return;
                        default:
                            Console.WriteLine("Invalid choice. Press any key to try again.");
                            Console.ReadKey();
                            break;
                    }
                } while (choice != "2");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in Handle Menu: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in Handle Menu: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in Handle Menu: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }
        static void SwitchToApplication(SqlConnection connection)
        {
            try
            {
                Console.Clear();
                if (!IsLicenseDefined(connection))
                {
                    Console.WriteLine("You don't have a defined license.");
                }
                else if (IsLicenseActive(connection) && !IsLicenseExpired(connection))
                {
                    Console.WriteLine("Switching to the application...");
                }
                else
                {
                    Console.WriteLine("You cannot switch to the application. Please make sure your license is active and not expired.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in SwitchToApplication: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in SwitchToApplication: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in SwitchToApplication: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            Console.ReadKey();
        }

        static string EncryptLicenseKey(string licenseKey)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(licenseKey);
                byte[] hashBytes = sha256.ComputeHash(inputBytes);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < hashBytes.Length; i++)
                {
                    sb.Append(hashBytes[i].ToString("x2"));
                }

                return sb.ToString();
            }
        }
        static string HashPassword(string password)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(password));
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }

                return builder.ToString();
            }
        }
        static string GetHardwareId()
        {
            string hardwareID = string.Empty;
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive");
            foreach (ManagementObject disk in searcher.Get())
            {
                hardwareID = disk["SerialNumber"].ToString();
                break;
            }
            return hardwareID;
        }

        static string GetProcessorId()
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor");
            ManagementObjectCollection collection = searcher.Get();

            string processorId = "";
            foreach (ManagementObject obj in collection)
            {
                processorId = obj["ProcessorId"].ToString();
                break;
            }

            return processorId;
        }

        static string GetMotherboardId()
        {
            ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard");
            ManagementObjectCollection collection = searcher.Get();

            string motherboardId = "";
            foreach (ManagementObject obj in collection)
            {
                motherboardId = obj["SerialNumber"].ToString();
                break;
            }

            return motherboardId;
        }

        static string GetMacAddress()
        {
            string macAddress = "";
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface networkInterface in networkInterfaces)
            {
                if (networkInterface.OperationalStatus == OperationalStatus.Up)
                {
                    macAddress = networkInterface.GetPhysicalAddress().ToString();
                    break;
                }
            }
            return macAddress;
        }
        static string GetLocalIpAddress()
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            return "N/A";
        }

        static string GetPublicIpAddress()
        {
            try
            {
                using (var webClient = new WebClient())
                {
                    return webClient.DownloadString("https://api64.ipify.org");
                }
            }
            catch (Exception)
            {
                return "N/A";
            }
        }
        static bool IsAlreadyRunning()
        {
            Process currentProcess = Process.GetCurrentProcess();
            string currentProcessName = currentProcess.ProcessName;

            Process[] processes = Process.GetProcessesByName(currentProcessName);
            return processes.Length > 1;
        }
        public static class AppSettings
        {
            public static string DbConnectionString { get; set; }
            static AppSettings()
            {
                DbConnectionString = "Data Source=YourServerIp;Initial Catalog=ZyixAuthSystemDB;User ID=Admin;Password=1;";
            }
        }
    }
}
