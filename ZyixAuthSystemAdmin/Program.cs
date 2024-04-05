using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;


namespace ZyixAuthSystemAdmin
{
    class Program
    {
        static void Main()
        {
            try
            {
                Console.Clear();
                Console.Title = "Zyix Auth System - Admin Login Panel";
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
                Console.WriteLine("Admin information;");
                Console.WriteLine(" HWID: " + userHwid);
                Console.WriteLine(" Motherboard ID: " + userMotherboardId);
                Console.WriteLine(" Processor ID: " + userGetProcessorId);
                Console.WriteLine(" MAC Address: " + userMacAddress);
                Console.WriteLine(" Local IPv4 Address: " + userLocalIpAddress);
                Console.WriteLine(" Public IP Address: " + userPublicIpAddress);
                Console.ForegroundColor = ConsoleColor.White;

                if (LoginAdmins())
                {
                    Console.WriteLine("Welcome to the Users Panel!");

                    using (SqlConnection connection = new SqlConnection(AppSettings.DbConnectionString))
                    {
                        if (connection.State == ConnectionState.Closed)
                            connection.Open();

                        AdminMenu(connection);

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
        static bool LoginAdmins()
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
                                    UpdateAdminHardwareInfo(connection, username, userHwid, userMacAddress, userLocalIpAddress, userPublicIpAddress, userMotherboardId, userProcessorId);
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
                                        Console.WriteLine("Press any key to exit.");
                                        Logger logger = new Logger(AppSettings.DbConnectionString);
                                        string logLevel = "Warning"; //Error', 'Warning', 'Info'
                                        string logDescription = $"Failed login attempt. System information did not match the user.";
                                        logger.LogTransaction(userID, logLevel, logDescription);

                                        Properties.Settings.Default.FailedLoginAttempts++;
                                        Properties.Settings.Default.Save();

                                        if (Properties.Settings.Default.FailedLoginAttempts >= maxFailedAttempts)
                                        {
                                            Console.Write("Do you think your hardware has changed? (yes/no)");
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
                                                            UpdateAdminHardwareInfo(connection, username, userHwid, userMacAddress, userLocalIpAddress, userPublicIpAddress, userMotherboardId, userProcessorId);
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
                                                    }
                                                }
                                                else
                                                {
                                                    Console.WriteLine("No security question found. Aborting hardware reset.");
                                                }
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

        static bool CheckUserSystemInfo(string username, string hwid, string macAddress, string processorId, string motherboardId, string userLocalIpAddress, string userPublicIpAddress, SqlConnection connection)
        {
            try
            {
                string query = "SELECT Username FROM Admins WHERE Username = @Username AND HardwareID = @HardwareID AND MacAddress = @MacAddress AND ProcessorID = @ProcessorID AND MotherboardID = @MotherboardID AND LocalIP = @LocalIP AND PublicIP = @PublicIP";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@HardwareID", hwid);
                    command.Parameters.AddWithValue("@MacAddress", macAddress);
                    command.Parameters.AddWithValue("@ProcessorID", processorId);
                    command.Parameters.AddWithValue("@MotherboardID", motherboardId);
                    UpdateIpAddress(username, userLocalIpAddress, userPublicIpAddress, connection);
                    command.Parameters.AddWithValue("@LocalIP", userLocalIpAddress);
                    command.Parameters.AddWithValue("@PublicIP", userPublicIpAddress);
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        return reader.Read();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in CheckUserSystemInfo: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");
                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in CheckUserSystemInfo: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in CheckUserSystemInfo: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
                return false;
            }
        }
        static void UpdateIpAddress(string username, string localIpAddress, string publicIpAddress, SqlConnection connection)
        {
            try
            {
                string query = "UPDATE Admins SET LocalIP = @LocalIP, PublicIP = @PublicIP WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@LocalIP", localIpAddress);
                    command.Parameters.AddWithValue("@PublicIP", publicIpAddress);

                    int rowsAffected = command.ExecuteNonQuery();

                    if (rowsAffected > 0)
                    {
                        Console.WriteLine($"IP addresses updated successfully for user: {username}");
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
        }
        static string GetStoredPassword(string username, SqlConnection connection)
        {
            try
            {
                string query = "SELECT Password FROM Admins WHERE Username = @Username";

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
                string hashedPassword = HashPassword(newPassword);
                string query = "UPDATE Admins SET Password = @Password WHERE Username = @Username";

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

        static void AdminMenu(SqlConnection connection)
        {
            try
            {
                string choice;
                do
                {
                    Console.Clear();
                    Console.Title = "Zyix Auth System - Admin Menu";
                    Console.WriteLine("Admin Menu:");
                    Console.WriteLine("1. Manage Users");
                    Console.WriteLine("2. Manage License");
                    Console.WriteLine("3. View Logs");
                    Console.WriteLine("4. Exit");

                    Console.Write("Enter your choice: ");
                    choice = Console.ReadLine();
                    switch (choice)
                    {
                        case "1":
                            ManageUsers(connection);
                            break;
                        case "2":
                            ManageLicense(connection);
                            break;
                        case "3":
                            ViewLogs(connection);
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
                Console.WriteLine($"An error occurred in AdminMenu: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in AdminMenu: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in AdminMenu: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }

        static void ManageUsers(SqlConnection connection)
        {
            try
            {
                string choice;
                do
                {
                    Console.Clear();
                    Console.Title = "Zyix Auth System - Manage Users Menu";
                    Console.WriteLine("Manage Users Menu:");
                    Console.WriteLine("1. Add User");
                    Console.WriteLine("2. Delete User");
                    Console.WriteLine("3. Update User E-mail");
                    Console.WriteLine("4. Update User Password");
                    Console.WriteLine("5. Delete User Hardware ID, Mac Address, Local IP, Public IP, Motherboard ID, Processor ID");
                    Console.WriteLine("6. Show All Users");
                    Console.WriteLine("7. Back to Admin Menu");

                    Console.Write("Enter your choice: ");
                    choice = Console.ReadLine();

                    switch (choice)
                    {
                        case "1":
                            AddUser(connection);
                            break;
                        case "2":
                            DeleteUser(connection);
                            break;
                        case "3":
                            UpdateUserEmail(connection);
                            break;
                        case "4":
                            UpdateUserPassword(connection);
                            break;
                        case "5":
                            DeleteUserInformation(connection);
                            break;
                        case "6":
                            ShowAllUsers(connection);
                            break;
                        case "7":
                            AdminMenu(connection);
                            break;
                        default:
                            Console.WriteLine("Invalid choice. Press any key to try again.");
                            Console.ReadKey();
                            break;
                    }
                } while (choice != "7");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in ManageUsers: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in ManageUsers: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in ManageUsers: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();

            }
        }
        // ADD USER
        static void AddUser(SqlConnection connection)
        {
            try
            {
                Console.WriteLine();
                Console.Write("Enter new username: ");
                string newUsername = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(newUsername))
                {
                    Console.WriteLine("Username cannot be empty. Please try again.");
                }
                else if (IsUsernameUnique(connection, newUsername))
                {
                    Console.Write("Enter new password: ");
                    string newPassword = Console.ReadLine();

                    if (string.IsNullOrWhiteSpace(newPassword))
                    {
                        Console.WriteLine("Password cannot be empty. Please try again.");
                    }
                    else
                    {
                        string newEmail;
                        bool isValidEmail = false;
                        do
                        {
                            Console.Write("Enter new email: ");
                            newEmail = Console.ReadLine();

                            if (IsValidEmail(newEmail))
                            {
                                isValidEmail = true;
                            }
                            else
                            {
                                Console.WriteLine("Invalid email format. Please enter a valid email address.");
                            }

                        } while (!isValidEmail);

                        InsertUser(connection, newUsername, newPassword, newEmail);
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Info"; //Error', 'Warning', 'Info'
                        string logDescription = $"User {newUsername} added successfully!";
                        logger.LogTransaction(userID, logLevel, logDescription);

                        Console.WriteLine($"User {newUsername} added successfully!");
                    }
                }
                else
                {
                    Console.WriteLine("This username is already taken. Please choose another one.");
                }

                Console.WriteLine("Press any key to return to the Admin Menu.");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in AddUser: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in AddUser: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in AddUser: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }
        static bool IsValidEmail(string email)
        {
            string pattern = @"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$";
            Regex regex = new Regex(pattern);
            return regex.IsMatch(email);
        }
        static void InsertUser(SqlConnection connection, string username, string password, string email)
        {
            try
            {
                string hashedPassword = HashPassword(password);
                string query = "INSERT INTO Users (Username, Password, Email) VALUES (@Username, @Password, @Email)";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@Password", hashedPassword);
                    command.Parameters.AddWithValue("@Email", email);
                    int rowsAffected = command.ExecuteNonQuery();
                    if (rowsAffected < 0)
                    {
                        Console.WriteLine($"Error adding user {username}. No rows affected.");
                    }

                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in InsertUser: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in InsertUser: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in InsertUser: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }

        static bool IsUsernameUnique(SqlConnection connection, string username)
        {
            try
            {
                string query = "SELECT COUNT(*) FROM Users WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);

                    int count = (int)command.ExecuteScalar();

                    return count == 0;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in IsUsernameUnique: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in IsUsernameUnique: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in IsUsernameUnique: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                return false;
            }
        }

        // ADD USER
        // DELETE USER
        static void DeleteUser(SqlConnection connection)
        {
            try
            {
                Console.WriteLine();
                Console.Write("Enter the username to delete: ");
                string usernameToDelete = Console.ReadLine();

                if (DoesUserExist(connection, usernameToDelete))
                {
                    Console.WriteLine($"Do you want to delete the user {usernameToDelete}? (yes/no)");
                    string response = Console.ReadLine().ToLower();

                    if (response == "yes")
                    {
                        DeleteUserLicenseKeys(connection, usernameToDelete);
                        DeleteUserFromDatabase(connection, usernameToDelete);
                        Console.WriteLine($"User {usernameToDelete} has been deleted along with their license keys.");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Info"; //Error', 'Warning', 'Info'
                        string logDescription = $"User {usernameToDelete} has been deleted along with their license keys.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                    else
                    {
                        Console.WriteLine($"User {usernameToDelete} has not been deleted.");
                    }
                }
                else
                {
                    Console.WriteLine($"User {usernameToDelete} not found.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in DeleteUser: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in DeleteUser: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in DeleteUser: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            Console.WriteLine("Press any key to return to the Admin Menu.");
            Console.ReadKey();
        }
        static void DeleteUserLicenseKeys(SqlConnection connection, string username)
        {
            try
            {
                int userId = GetUserId(connection, username);
                string query = "DELETE FROM Licenses WHERE UserID = @UserID";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@UserID", userId);
                    command.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in DeleteUserLicenseKeys: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in DeleteUserLicenseKeys: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in DeleteUserLicenseKeys: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }

        static int GetUserId(SqlConnection connection, string username)
        {
            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                string queryUsers = "SELECT UserID FROM Users WHERE Username = @Username";
                string queryAdmin = "SELECT AdminID FROM Admins WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(queryUsers, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    object result = command.ExecuteScalar();

                    if (result != null)
                    {
                        return (int)result;
                    }
                    else
                    {
                        using (SqlCommand adminCommand = new SqlCommand(queryAdmin, connection))
                        {
                            adminCommand.Parameters.AddWithValue("@Username", username);
                            object adminResult = adminCommand.ExecuteScalar();

                            return adminResult != null ? (int)adminResult : -1;
                        }
                    }
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
#pragma warning disable CS0162 // Ulaşılamayan kod algılandı
            connection.Close();
#pragma warning restore CS0162 // Ulaşılamayan kod algılandı
        }
        static bool DoesUserExist(SqlConnection connection, string username)
        {
            try
            {
                string query = "SELECT COUNT(*) FROM Users WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);

                    int count = (int)command.ExecuteScalar();

                    return count > 0;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in DoesUserExist: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in DoesUserExist: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in DoesUserExist: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                return false;
            }
        }


        static void DeleteUserFromDatabase(SqlConnection connection, string username)
        {
            try
            {
                string query = "DELETE FROM Users WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in DeleteUserFromDatabase: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in DeleteUserFromDatabase: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in DeleteUserFromDatabase: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }
        // DELETE USER
        // UPDATE USER EMAİL
        static void UpdateUserEmail(SqlConnection connection)
        {
            try
            {
                Console.WriteLine();
                Console.Write("Enter the username to update email: ");
                string usernameToUpdate = Console.ReadLine();

                if (DoesUserExist(connection, usernameToUpdate))
                {
                    Console.Write("Enter the new email address: ");
                    string newEmail = Console.ReadLine();

                    if (IsValidEmail(newEmail))
                    {
                        UpdateUserEmailInDatabase(connection, usernameToUpdate, newEmail);
                        Console.WriteLine($"Email for user {usernameToUpdate} has been updated.");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Info"; //Error', 'Warning', 'Info'
                        string logDescription = $"Email for user {usernameToUpdate} has been updated.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                    else
                    {
                        Console.WriteLine("Invalid email format. Email has not been updated.");
                    }
                }
                else
                {
                    Console.WriteLine($"User {usernameToUpdate} not found.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in UpdateUserEmail: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in UpdateUserEmail: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in UpdateUserEmail: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
            }
            Console.WriteLine("Press any key to return to the Admin Menu.");
            Console.ReadKey();
        }

        static void UpdateUserEmailInDatabase(SqlConnection connection, string username, string newEmail)
        {
            try
            {
                string query = "UPDATE Users SET Email = @Email WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@Email", newEmail);
                    command.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in UpdateUserEmailInDatabase: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in UpdateUserEmailInDatabase: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in UpdateUserEmailInDatabase: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }

        // UPDATE USER EMAİL
        // UPDATE USER PASSWORD
        static void UpdateUserPassword(SqlConnection connection)
        {
            try
            {
                Console.WriteLine();
                Console.Write("Enter the username to update password: ");
                string usernameToUpdate = Console.ReadLine();

                if (DoesUserExist(connection, usernameToUpdate))
                {
                    Console.Write("Enter the new password: ");
                    string newPassword = Console.ReadLine();

                    UpdateUserPasswordInDatabase(connection, usernameToUpdate, newPassword);
                    Console.WriteLine($"Password for user {usernameToUpdate} has been updated.");
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Info"; //Error', 'Warning', 'Info'
                    string logDescription = $"Password for user {usernameToUpdate} has been updated.";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                else
                {
                    Console.WriteLine($"User {usernameToUpdate} not found.");
                }

                Console.WriteLine("Press any key to return to the Admin Menu.");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in UpdateUserPassword: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in UpdateUserPassword: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in UpdateUserPassword: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }
        static void UpdateUserPasswordInDatabase(SqlConnection connection, string username, string newPassword)
        {
            try
            {
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
                Console.WriteLine($"An error occurred in UpdateUserPasswordInDatabase: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in UpdateUserPasswordInDatabase: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in UpdateUserPasswordInDatabase: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }

        // DELETE USER INFORMATİON
        static void DeleteUserInformation(SqlConnection connection)
        {
            try
            {
                Console.WriteLine();
                Console.Write("Enter the username to delete information: ");
                string usernameToDeleteInfo = Console.ReadLine();

                if (DoesUserExist(connection, usernameToDeleteInfo))
                {
                    Console.WriteLine($"Do you want to delete the information of user {usernameToDeleteInfo}? (yes/no)");
                    string response = Console.ReadLine().ToLower();

                    if (response == "yes")
                    {
                        DeleteUserInformationFromDatabase(connection, usernameToDeleteInfo);
                        Console.WriteLine($"Information of user {usernameToDeleteInfo} has been deleted.");
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Info"; //Error', 'Warning', 'Info'
                        string logDescription = $"Information of user {usernameToDeleteInfo} has been deleted.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                    else
                    {
                        Console.WriteLine($"Information of user {usernameToDeleteInfo} has not been deleted.");
                    }
                }
                else
                {
                    Console.WriteLine($"User {usernameToDeleteInfo} not found.");
                }

                Console.WriteLine("Press any key to return to the Admin Menu.");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in DeleteUserInformation: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in DeleteUserInformation: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in DeleteUserInformation: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }
        static void UpdateAdminHardwareInfo(SqlConnection connection, string username, string newHwid, string newMacAddress, string newLocalIP, string newPublicIP, string newMotherboardID, string newProcessorID)
        {
            try
            {
                string existingHardwareInfoQuery = "SELECT HardwareID, MacAddress, LocalIP, PublicIP, MotherboardID, ProcessorID FROM Admins WHERE Username = @Username";
                string existingHwid, existingMacAddress, existingLocalIP, existingPublicIP, existingMotherboardID, existingProcessorID;

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

                /*Console.WriteLine("allParamsAreEmpty: " + allParamsAreEmpty);

                Console.WriteLine("existingHwid: " + existingHwid);
                Console.WriteLine("existingMacAddress: " + existingMacAddress);
                Console.WriteLine("existingLocalIP: " + existingLocalIP);
                Console.WriteLine("existingPublicIP: " + existingPublicIP);
                Console.WriteLine("existingMotherboardID: " + existingMotherboardID);
                Console.WriteLine("existingProcessorID: " + existingProcessorID);*/

                if (allParamsAreEmpty)
                {
                    string query = "UPDATE Admins SET ";
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
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in UpdateUserHardwareInfo: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    int logUserID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error";
                    string logDescription = $"An error occurred in UpdateUserHardwareInfo: {ex.Message} User IP: {userPublicIpAddress}";
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
        }

        static void DeleteUserInformationFromDatabase(SqlConnection connection, string username)
        {
            try
            {
                string usersQuery = "UPDATE Users SET HardwareID = NULL, MacAddress = NULL, LocalIP = NULL, PublicIP = NULL, MotherboardID = NULL, ProcessorID = NULL WHERE Username = @Username";

                using (SqlCommand usersCommand = new SqlCommand(usersQuery, connection))
                {
                    usersCommand.Parameters.AddWithValue("@Username", username);
                    usersCommand.ExecuteNonQuery();
                }

                string adminsQuery = "UPDATE Admins SET HardwareID = NULL, MacAddress = NULL, LocalIP = NULL, PublicIP = NULL, MotherboardID = NULL, ProcessorID = NULL WHERE Username = @Username";

                using (SqlCommand adminsCommand = new SqlCommand(adminsQuery, connection))
                {
                    adminsCommand.Parameters.AddWithValue("@Username", username);
                    adminsCommand.ExecuteNonQuery();
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
        }
        // DELETE USER INFORMATİON

        //ShowAllUsers
        static void ShowAllUsers(SqlConnection connection)
        {
            try
            {
                List<UserInfo> users = GetAllUsersWithDetails(connection);

                using (StreamWriter writer = new StreamWriter("All-Users.txt"))
                {
                    foreach (var user in users)
                    {
                        writer.WriteLine($"Username: {user.Username}");
                        writer.WriteLine($"Email: {user.Email}");

                        foreach (var detail in user.Details)
                        {
                            writer.WriteLine(detail);
                        }

                        writer.WriteLine();
                    }
                }

                int userID = GetUserId(connection, loggedInUsername);
                Logger logger = new Logger(AppSettings.DbConnectionString);
                string logLevel = "Info"; //Error', 'Warning', 'Info'
                string logDescription = "All users have been written to 'All-Users.txt";
                logger.LogTransaction(userID, logLevel, logDescription);

                Console.WriteLine("All users have been written to 'All-Users.txt'.");
                Console.WriteLine("Press any key to return to the Admin Menu.");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in ShowAllUsers: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in ShowAllUsers: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in ShowAllUsers: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.WriteLine("Press any key to return to the Admin Menu.");
                Console.ReadKey();
            }
        }


        static List<UserInfo> GetAllUsersWithDetails(SqlConnection connection)
        {
            try
            {
                List<UserInfo> users = new List<UserInfo>();

                string query = "SELECT * FROM Users";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            UserInfo user = new UserInfo
                            {
                                Username = reader["Username"].ToString(),
                                Email = reader["Email"].ToString(),
                                LicenseKey = reader["LicenseKey"].ToString(),
                                MacAddress = reader["MacAddress"].ToString(),
                                LocalIP = reader["LocalIP"].ToString(),
                                PublicIP = reader["PublicIP"].ToString(),
                                MotherboardID = reader["MotherboardID"].ToString(),
                                ProcessorID = reader["ProcessorID"].ToString(),
                                HardwareID = reader["HardwareID"].ToString()
                            };
                            users.Add(user);
                        }
                    }
                }
                return users;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in GetAllUsersWithDetails: {ex.Message}");
                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in GetAllUsersWithDetails: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in GetAllUsersWithDetails: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                return null;
            }
        }

        public class UserInfo
        {
            public string Username { get; set; }
            public string Email { get; set; }
            public string LicenseKey { get; set; }
            public string MacAddress { get; set; }
            public string LocalIP { get; set; }
            public string PublicIP { get; set; }
            public string MotherboardID { get; set; }
            public string ProcessorID { get; set; }
            public string HardwareID { get; set; }
            public List<string> Details
            {
                get
                {
                    var details = new List<string>();

                    if (!string.IsNullOrEmpty(LicenseKey))
                        details.Add($"LicenseKey: {LicenseKey}");
                    else
                        details.Add("LicenseKey: Information not available.");

                    if (!string.IsNullOrEmpty(MacAddress))
                        details.Add($"MacAddress: {MacAddress}");
                    else
                        details.Add("MacAddress: Information not available.");

                    if (!string.IsNullOrEmpty(LocalIP))
                        details.Add($"LocalIP: {LocalIP}");
                    else
                        details.Add("LocalIP: Information not available.");

                    if (!string.IsNullOrEmpty(PublicIP))
                        details.Add($"PublicIP: {PublicIP}");
                    else
                        details.Add("PublicIP: Information not available.");

                    if (!string.IsNullOrEmpty(MotherboardID))
                        details.Add($"MotherboardID: {MotherboardID}");
                    else
                        details.Add("MotherboardID: Information not available.");

                    if (!string.IsNullOrEmpty(ProcessorID))
                        details.Add($"ProcessorID: {ProcessorID}");
                    else
                        details.Add("ProcessorID: Information not available.");

                    if (!string.IsNullOrEmpty(HardwareID))
                        details.Add($"HardwareID: {HardwareID}");
                    else
                        details.Add("HardwareID: Information not available.");

                    return details;
                }
            }
        }
        //ShowAllUsers
        static void ManageLicense(SqlConnection connection)
        {
            string choice;
            do
            {
                try
                {
                    Console.Clear();
                    Console.Title = "Zyix Auth System - Manage License Menu";
                    Console.WriteLine("Manage License Menu:");
                    Console.WriteLine("1. Add License Key");
                    Console.WriteLine("2. Delete License Key");
                    Console.WriteLine("3. Update User License Key");
                    Console.WriteLine("4. Delete User License Key");
                    Console.WriteLine("5. Update User License Expiration Date");
                    Console.WriteLine("6. Update License Username");
                    Console.WriteLine("7. Update License is Active");
                    Console.WriteLine("8. Show All License");
                    Console.WriteLine("9. Back to Admin Menu");

                    Console.Write("Enter your choice: ");
                    choice = Console.ReadLine();

                    switch (choice)
                    {
                        case "1":
                            AddLicenseKey(connection);
                            break;
                        case "2":
                            DeleteLicenseKey(connection);
                            break;
                        case "3":
                            UpdateUserLicenseKey(connection);
                            break;
                        case "4":
                            DeleteUserLicenseKey(connection);
                            break;
                        case "5":
                            UpdateUserLicenseExpirationDate(connection);
                            break;
                        case "6":
                            UpdateLicenseUsername(connection);
                            break;
                        case "7":
                            UpdateLicenseActive(connection);
                            break;
                        case "8":
                            ShowAllLicense(connection);
                            break;
                        case "9":
                            AdminMenu(connection);
                            break;
                        default:
                            Console.WriteLine("Invalid choice. Press any key to try again.");
                            Console.ReadKey();
                            break;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"An error occurred in ManageLicense: {ex.Message}");
                    Console.WriteLine("Please contact the software developer for assistance.");

                    try
                    {
                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                        string logDescription = $"An error occurred in ManageLicense: {ex.Message}";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                    catch (Exception logEx)
                    {
                        string userPublicIpAddress = GetPublicIpAddress();
                        FileLogger logger = new FileLogger("Logs.log");
                        logger.LogError($"An error occurred in ManageLicense: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                    }
                    return;
                }
            } while (choice != "9");
            Console.ReadKey();
        }
        // ADD LİCENSE
        static void AddLicenseKey(SqlConnection connection)
        {
            try
            {
                Console.Clear();
                Console.Write("Enter the expiration days for the license key: ");

                if (int.TryParse(Console.ReadLine(), out int expirationDays) && expirationDays > 0)
                {
                    DateTime startDate = DateTime.Now;
                    DateTime expirationDate = startDate.AddDays(expirationDays);

                    string newLicenseKey;
                    do
                    {
                        newLicenseKey = GenerateRandomLicenseKey();
                    } while (!IsLicenseKeyUnique(connection, newLicenseKey));

                    string encryptedLicenseKey = EncryptLicenseKey(newLicenseKey);
                    InsertLicenseKey(connection, encryptedLicenseKey, newLicenseKey, startDate, expirationDate);

                    Console.WriteLine($"License key has been added.");
                    Console.WriteLine($"New License Key: {newLicenseKey}");
                    Console.WriteLine($"Start Date: {startDate}");
                    Console.WriteLine($"Expiration Date: {expirationDate}");

                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Info"; //Error', 'Warning', 'Info'
                    string logDescription = "License key has been added.";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                else
                {
                    Console.WriteLine("Invalid expiration days. Please enter a positive integer.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in AddLicenseKey: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in AddLicenseKey: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in AddLicenseKey: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
            }
            Console.WriteLine("Press any key to return to the Manage License Menu");
            Console.ReadKey();
        }

        static bool IsLicenseKeyUnique(SqlConnection connection, string licenseKey)
        {
            try
            {
                string query = "SELECT COUNT(*) FROM Licenses WHERE LicenseKey = @LicenseKey";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@LicenseKey", licenseKey);

                    int count = (int)command.ExecuteScalar();

                    return count == 0;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred in IsLicenseKeyUnique: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in IsLicenseKeyUnique: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in IsLicenseKeyUnique: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                return false;
            }
        }
        static void InsertLicenseKey(SqlConnection connection, string newLicenseKey, string unencryptedLicenseKey, DateTime startDate, DateTime expirationDate)
        {
            try
            {
                string query = "INSERT INTO Licenses (LicenseKey, UnencryptedLicenseKey, IsActive, StartDate, ExpirationDate) VALUES (@LicenseKey, @UnencryptedLicenseKey, @IsActive, @StartDate, @ExpirationDate)";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@LicenseKey", newLicenseKey);
                    command.Parameters.AddWithValue("@UnencryptedLicenseKey", unencryptedLicenseKey);
                    command.Parameters.AddWithValue("@IsActive", false);
                    command.Parameters.AddWithValue("@StartDate", startDate);
                    command.Parameters.AddWithValue("@ExpirationDate", expirationDate);

                    command.ExecuteNonQuery();
                }

                Console.WriteLine("License key inserted successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred in InsertLicenseKey: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in InsertLicenseKey: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in InsertLicenseKey: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }
        // ADD LİCENSE

        // DELETE LİCENSE
        static void DeleteLicenseKey(SqlConnection connection)
        {
            try
            {
                Console.Clear();
                Console.Write("Enter the license key to delete: ");
                string licenseKeyToDelete = Console.ReadLine();

                string encryptedLicenseKey = EncryptLicenseKey(licenseKeyToDelete);

                if (DoesLicenseExist(connection, encryptedLicenseKey))
                {
                    string username = GetUsernameFromLicense(connection, encryptedLicenseKey);

                    Console.WriteLine($"Do you want to delete the license key {licenseKeyToDelete} of user {username}? (yes/no)");
                    string response = Console.ReadLine().ToLower();

                    if (response == "yes")
                    {
                        DeleteLicenseKeyFromDatabase(connection, encryptedLicenseKey);
                        Console.WriteLine($"License key {licenseKeyToDelete} of user {username} has been deleted.");

                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Info"; //Error', 'Warning', 'Info'
                        string logDescription = $"License key {licenseKeyToDelete} of user {username} has been deleted.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                    else
                    {
                        Console.WriteLine($"License key {licenseKeyToDelete} of user {username} has not been deleted.");
                    }
                }
                else
                {
                    Console.WriteLine($"License key {licenseKeyToDelete} not found.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred in DeleteLicenseKey: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in DeleteLicenseKey: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in DeleteLicenseKey: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.WriteLine("Press any key to return to the Admin Menu.");
                Console.ReadKey();
            }
            Console.WriteLine("Press any key to return to the Manage License Menu");
            Console.ReadKey();
        }


        static bool DoesLicenseExist(SqlConnection connection, string encryptedLicenseKey)
        {
            try
            {
                string query = "SELECT COUNT(*) FROM Licenses WHERE LicenseKey = @EncryptedLicenseKey";
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@EncryptedLicenseKey", encryptedLicenseKey);
                    int count = (int)command.ExecuteScalar();
                    return count > 0;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred in DoesLicenseExist: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in DoesLicenseExist: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in DoesLicenseExist: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                return false;
            }
        }
        static string GetUsernameFromLicense(SqlConnection connection, string encryptedLicenseKey)
        {
            try
            {
                string query = "SELECT U.Username FROM Users U INNER JOIN Licenses L ON U.UserID = L.UserID WHERE L.LicenseKey = @EncryptedLicenseKey";
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@EncryptedLicenseKey", encryptedLicenseKey);
                    object result = command.ExecuteScalar();
                    return result != null ? result.ToString() : string.Empty;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred in GetUsernameFromLicense: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in GetUsernameFromLicense: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in GetUsernameFromLicense: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                return string.Empty;
            }
        }
        static void DeleteLicenseKeyFromDatabase(SqlConnection connection, string encryptedLicenseKey)
        {
            try
            {
                string updateQuery = "UPDATE Users SET LicenseKey = NULL WHERE UserID IN (SELECT UserID FROM Licenses WHERE LicenseKey = @EncryptedLicenseKey)";
                using (SqlCommand updateCommand = new SqlCommand(updateQuery, connection))
                {
                    updateCommand.Parameters.AddWithValue("@EncryptedLicenseKey", encryptedLicenseKey);
                    updateCommand.ExecuteNonQuery();
                }

                string deleteQuery = "DELETE FROM Licenses WHERE LicenseKey = @EncryptedLicenseKey";
                using (SqlCommand deleteCommand = new SqlCommand(deleteQuery, connection))
                {
                    deleteCommand.Parameters.AddWithValue("@EncryptedLicenseKey", encryptedLicenseKey);
                    deleteCommand.ExecuteNonQuery();
                }

                Console.WriteLine($"License key {encryptedLicenseKey} has been deleted.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred in DeleteLicenseKeyFromDatabase: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in DeleteLicenseKeyFromDatabase: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in DeleteLicenseKeyFromDatabase: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
            }
            Console.WriteLine("Press any key to return to the Admin Menu.");
            Console.ReadKey();
        }
        // DELETE LİCENSE

        // UPDATE USER LİCENSE
        static void UpdateUserLicenseKey(SqlConnection connection)
        {
            try
            {
                Console.Clear();
                Console.Write("Enter the username to update license key: ");
                string usernameToUpdate = Console.ReadLine();

                if (DoesUserExist(connection, usernameToUpdate))
                {
                    int userId = GetUserId(connection, usernameToUpdate);

                    if (DoesUserHaveLicense(connection, userId))
                    {
                        string newLicenseKey;

                        do
                        {
                            newLicenseKey = GenerateRandomLicenseKey();
                        } while (!IsLicenseKeyUnique(connection, newLicenseKey));

                        string encryptedLicenseKey = EncryptLicenseKey(newLicenseKey);

                        UpdateLicenseTable(connection, userId, encryptedLicenseKey);

                        Console.WriteLine($"License key for user {usernameToUpdate} has been updated.");
                        Console.WriteLine($"New License Key: {newLicenseKey}");

                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Info"; //Error', 'Warning', 'Info'
                        string logDescription = $"License key for user {usernameToUpdate} has been updated.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                    else
                    {
                        Console.WriteLine($"User {usernameToUpdate} does not have a license. Please generate a license first.");
                    }
                }
                else
                {
                    Console.WriteLine($"User {usernameToUpdate} not found.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred in UpdateUserLicenseKey: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in UpdateUserLicenseKey: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in UpdateUserLicenseKey: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
            }
            Console.WriteLine("Press any key to return to the Manage License Menu");
            Console.ReadKey();
        }

        static bool DoesUserHaveLicense(SqlConnection connection, int userId)
        {
            try
            {
                string query = "SELECT COUNT(*) FROM Licenses WHERE UserID = @UserID";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@UserID", userId);

                    int count = (int)command.ExecuteScalar();

                    return count > 0;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred in DoesUserHaveLicense: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in DoesUserHaveLicense: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in DoesUserHaveLicense: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                return false;
            }
        }

        static void UpdateLicenseTable(SqlConnection connection, int userId, string newLicenseKey)
        {
            try
            {
                string encryptedLicenseKey = EncryptLicenseKey(newLicenseKey);

                string query = "UPDATE Licenses SET LicenseKey = @LicenseKey WHERE UserID = @UserID";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@LicenseKey", encryptedLicenseKey);
                    command.Parameters.AddWithValue("@UserID", userId);
                    command.ExecuteNonQuery();
                }
                UpdateLicenseKeyInDatabase(connection, userId, encryptedLicenseKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred in UpdateLicenseTable: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in UpdateLicenseTable: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in UpdateLicenseTable: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }

        static void UpdateLicenseKeyInDatabase(SqlConnection connection, int userId, string encryptedLicenseKey)
        {
            try
            {
                string query = "UPDATE Users SET LicenseKey = @LicenseKey WHERE UserID = @UserID";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@LicenseKey", encryptedLicenseKey);
                    command.Parameters.AddWithValue("@UserID", userId);

                    command.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred in UpdateLicenseKeyInDatabase: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in UpdateLicenseKeyInDatabase: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in UpdateLicenseKeyInDatabase: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }

        // UPDATE USER LİCENSE

        // DELETE USER LİCENSE
        static void DeleteUserLicenseKey(SqlConnection connection)
        {
            try
            {
                Console.Clear();
                Console.Write("Enter the username to delete license key: ");
                string usernameToDeleteLicenseKey = Console.ReadLine();

                if (DoesUserExist(connection, usernameToDeleteLicenseKey))
                {
                    Console.WriteLine($"Do you want to delete the license key of user {usernameToDeleteLicenseKey}? (yes/no)");
                    string response = Console.ReadLine().ToLower();

                    if (response == "yes")
                    {
                        DeleteUserLicenseKeyFromDatabase(connection, usernameToDeleteLicenseKey);
                        Console.WriteLine($"License key of user {usernameToDeleteLicenseKey} has been deleted.");

                        int userID = GetUserId(connection, loggedInUsername);
                        Logger logger = new Logger(AppSettings.DbConnectionString);
                        string logLevel = "Info"; //Error', 'Warning', 'Info'
                        string logDescription = $"License key of user {usernameToDeleteLicenseKey} has been deleted.";
                        logger.LogTransaction(userID, logLevel, logDescription);
                    }
                    else
                    {
                        Console.WriteLine($"License key of user {usernameToDeleteLicenseKey} has not been deleted.");
                    }
                }
                else
                {
                    Console.WriteLine($"User {usernameToDeleteLicenseKey} not found.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred in DeleteUserLicenseKey: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in DeleteUserLicenseKey: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in DeleteUserLicenseKey: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
            }
            Console.WriteLine("Press any key to return to the Manage License Menu");
            Console.ReadKey();
        }
        static void DeleteUserLicenseKeyFromDatabase(SqlConnection connection, string username)
        {
            try
            {
                string query = "UPDATE Users SET LicenseKey = NULL WHERE Username = @Username";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred in DeleteUserLicenseKeyFromDatabase: " + ex.Message);
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in DeleteUserLicenseKeyFromDatabase: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in DeleteUserLicenseKeyFromDatabase: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }
        // DELETE USER LİCENSE

        //UpdateUserLicenseExpirationDate
        static void UpdateUserLicenseExpirationDate(SqlConnection connection)
        {
            try
            {
                Console.Clear();
                Console.Write("Enter the username to update license expiration date: ");
                string usernameToUpdateExpirationDate = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(usernameToUpdateExpirationDate))
                {
                    Console.WriteLine("Username cannot be empty. Please try again.");
                    return;
                }

                Console.Write("Enter the number of days to extend the license expiration date: ");
                if (!int.TryParse(Console.ReadLine(), out int daysToAdd) || daysToAdd <= 0)
                {
                    Console.WriteLine("Invalid number of days. Please enter a valid positive number.");
                    Console.ReadLine();
                    return;
                }

                if (DoesUserExist(connection, usernameToUpdateExpirationDate))
                {
                    DateTime currentExpirationDate = GetUserLicenseExpirationDate(connection, usernameToUpdateExpirationDate);
                    DateTime newExpirationDate = currentExpirationDate.AddDays(daysToAdd);

                    string updateQuery = "UPDATE Licenses SET ExpirationDate = @NewExpirationDate WHERE UserID = (SELECT UserID FROM Users WHERE Username = @Username)";

                    using (SqlCommand updateCommand = new SqlCommand(updateQuery, connection))
                    {
                        updateCommand.Parameters.AddWithValue("@NewExpirationDate", newExpirationDate);
                        updateCommand.Parameters.AddWithValue("@Username", usernameToUpdateExpirationDate);
                        updateCommand.ExecuteNonQuery();
                    }

                    Console.WriteLine($"License expiration date for user {usernameToUpdateExpirationDate} updated successfully.");

                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Info"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"License expiration date for user {usernameToUpdateExpirationDate} updated successfully.";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                else
                {
                    Console.WriteLine($"User {usernameToUpdateExpirationDate} not found.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred in UpdateUserLicenseExpirationDate: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in UpdateUserLicenseExpirationDate: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in UpdateUserLicenseExpirationDate: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            Console.WriteLine("Press any key to return to the Manage License Menu");
            Console.ReadKey();
        }

        static DateTime GetUserLicenseExpirationDate(SqlConnection connection, string username)
        {
            try
            {
                string query = "SELECT L.ExpirationDate FROM Licenses L INNER JOIN Users U ON L.UserID = U.UserID WHERE U.Username = @Username";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);

                    object result = command.ExecuteScalar();

                    if (result != null && DateTime.TryParse(result.ToString(), out DateTime expirationDate))
                    {
                        return expirationDate;
                    }

                    return DateTime.MinValue; // veya başka bir varsayılan değer
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while getting user's license expiration date: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while getting user's license expiration date: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while getting user's license expiration date: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                return DateTime.MinValue;
            }
        }
        //UpdateUserLicenseExpirationDate

        //UpdateLicenseUsername
        static void UpdateLicenseUsername(SqlConnection connection)
        {
            try
            {
                Console.Clear();
                Console.Write("Enter the license key to update username: ");
                string licenseKeyToUpdate = Console.ReadLine();

                string encryptedLicenseKey = EncryptLicenseKey(licenseKeyToUpdate);

                if (!DoesLicenseExist(connection, encryptedLicenseKey))
                {
                    Console.WriteLine($"Encrypted license key {encryptedLicenseKey} not found.");
                    Console.WriteLine("Press any key to return to the Admin Menu.");
                    Console.ReadKey();
                    return;
                }

                string currentUsername = GetUsernameFromLicense(connection, encryptedLicenseKey);

                Console.Write($"Enter the new username for the license key {licenseKeyToUpdate}: ");
                string newUsername = Console.ReadLine();

                if (!DoesUserExist(connection, newUsername))
                {
                    Console.WriteLine($"The new username {newUsername} does not exist. Please choose a different username.");
                    Console.WriteLine("Press any key to return to the Admin Menu.");
                    Console.ReadKey();
                    return;
                }

                Console.WriteLine($"Do you want to update the username associated with the license key {licenseKeyToUpdate} from {currentUsername} to {newUsername}? (yes/no)");
                string response = Console.ReadLine().ToLower();

                if (response == "yes")
                {
                    UpdateLicenseUsernameInDatabase(connection, encryptedLicenseKey, newUsername);
                    Console.WriteLine($"Username associated with the license key {licenseKeyToUpdate} has been updated from {currentUsername} to {newUsername}.");
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Info"; //Error', 'Warning', 'Info'
                    string logDescription = $"Username associated with the license key {licenseKeyToUpdate} has been updated from {currentUsername} to {newUsername}.";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                else if (response == "no")
                {
                    Console.WriteLine("Username update canceled.");
                }
                else
                {
                    Console.WriteLine("Invalid response. Username update canceled.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while updating the username for the license key: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while updating the username for the license key: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while updating the username for the license key: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            Console.WriteLine("Press any key to return to the Manage License Menu");
            Console.ReadKey();
        }
        static void UpdateLicenseUsernameInDatabase(SqlConnection connection, string encryptedLicenseKey, string newUsername)
        {
            try
            {
                string getUserIdQuery = "SELECT UserID FROM Users WHERE Username = @NewUsername";

                using (SqlCommand getUserIdCommand = new SqlCommand(getUserIdQuery, connection))
                {
                    getUserIdCommand.Parameters.AddWithValue("@NewUsername", newUsername);

                    object result = getUserIdCommand.ExecuteScalar();

                    if (result != null)
                    {
                        int userId = (int)result;
                        string updateQuery = "UPDATE Licenses SET UserID = @UserID WHERE LicenseKey = @EncryptedLicenseKey";

                        using (SqlCommand updateCommand = new SqlCommand(updateQuery, connection))
                        {
                            updateCommand.Parameters.AddWithValue("@UserID", userId);
                            updateCommand.Parameters.AddWithValue("@EncryptedLicenseKey", encryptedLicenseKey);

                            updateCommand.ExecuteNonQuery();
                        }

                        string updateUserLicenseQuery = "UPDATE Users SET LicenseKey = @EncryptedLicenseKey WHERE UserID = @UserID";

                        using (SqlCommand updateUserLicenseCommand = new SqlCommand(updateUserLicenseQuery, connection))
                        {
                            updateUserLicenseCommand.Parameters.AddWithValue("@UserID", userId);
                            updateUserLicenseCommand.Parameters.AddWithValue("@EncryptedLicenseKey", encryptedLicenseKey);
                            updateUserLicenseCommand.ExecuteNonQuery();
                        }
                    }
                    else
                    {
                        Console.WriteLine($"User not found for the new username {newUsername}.");
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while updating license username: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while updating license username: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while updating license username: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }

        //UpdateLicenseUsername

        //UpdateLicenseActive
        static void UpdateLicenseActive(SqlConnection connection)
        {
            try
            {
                Console.Clear();
                Console.Write("Enter the license key to update active status: ");
                string licenseKeyToUpdate = Console.ReadLine();

                string encryptedLicenseKey = EncryptLicenseKey(licenseKeyToUpdate);

                if (!DoesLicenseExist(connection, encryptedLicenseKey))
                {
                    Console.WriteLine($"License key {licenseKeyToUpdate} not found.");
                    Console.WriteLine("Press any key to return to the Admin Menu.");
                    Console.ReadKey();
                    return;
                }

                Console.Write("Enter the new active status (true/false): ");
                if (!bool.TryParse(Console.ReadLine(), out bool newActiveStatus))
                {
                    Console.WriteLine("Invalid input. Please enter true or false.");
                    Console.WriteLine("Press any key to return to the Admin Menu.");
                    Console.ReadKey();
                    return;
                }

                UpdateLicenseActiveStatusInDatabase(connection, encryptedLicenseKey, newActiveStatus);
                Console.WriteLine($"Active status associated with the license key {licenseKeyToUpdate} has been updated to {newActiveStatus}.");

                int userID = GetUserId(connection, loggedInUsername);
                Logger logger = new Logger(AppSettings.DbConnectionString);
                string logLevel = "Info"; //Error', 'Warning', 'Info'
                string logDescription = $"Active status associated with the license key {licenseKeyToUpdate} has been updated to {newActiveStatus}.";
                logger.LogTransaction(userID, logLevel, logDescription);

                Console.WriteLine("Press any key to return to the Admin Menu.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while updating license active status: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while updating license active status: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while updating license active status: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
            }
            Console.WriteLine("Press any key to return to the Manage License Menu");
            Console.ReadKey();
        }
        static void UpdateLicenseActiveStatusInDatabase(SqlConnection connection, string encryptedLicenseKey, bool newActiveStatus)
        {
            try
            {
                string updateQuery = "UPDATE Licenses SET IsActive = @NewActiveStatus WHERE LicenseKey = @EncryptedLicenseKey";

                using (SqlCommand command = new SqlCommand(updateQuery, connection))
                {
                    command.Parameters.AddWithValue("@NewActiveStatus", newActiveStatus);
                    command.Parameters.AddWithValue("@EncryptedLicenseKey", encryptedLicenseKey);

                    command.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while updating license active status in the database: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while updating license active status in the database: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while updating license active status in the database: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }

        //UpdateLicenseActive

        //ShowAllLicense
        static void ShowAllLicense(SqlConnection connection)
        {
            try
            {
                Console.Clear();
                List<LicenseInfo> licenses = GetAllLicensesWithDetails(connection);
                using (StreamWriter writer = new StreamWriter("All-Licenses.txt"))
                {
                    foreach (var license in licenses)
                    {
                        writer.WriteLine($"Encrypted License: {license.EncryptedLicenseKey}");
                        writer.WriteLine($"Unencrypted License: {license.UnencryptedLicenseKey}");
                        if (license.UserID.HasValue)
                            writer.WriteLine($"UserID: {license.UserID}");
                        else
                            writer.WriteLine("UserID: This license is not assigned to a user.");
                        writer.WriteLine($"IsActive: {license.IsActive}");
                        writer.WriteLine($"Start Date: {license.StartDate}");
                        writer.WriteLine($"Expiration Date: {license.ExpirationDate}");
                        writer.WriteLine("------------------------------------------------------------------------------------");
                    }
                }
                int userID = GetUserId(connection, loggedInUsername);
                Logger logger = new Logger(AppSettings.DbConnectionString);
                string logLevel = "Info"; //Error', 'Warning', 'Info'
                string logDescription = "All licenses and their details have been written to 'AllLicenses.txt'.";
                logger.LogTransaction(userID, logLevel, logDescription);

                Console.WriteLine("All licenses and their details have been written to 'AllLicenses.txt'.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while showing all licenses: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while showing all licenses: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while showing all licenses: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
            Console.WriteLine("Press any key to return to the Manage License Menu");
            Console.ReadKey();
        }
        static List<LicenseInfo> GetAllLicensesWithDetails(SqlConnection connection)
        {
            try
            {
                List<LicenseInfo> licenses = new List<LicenseInfo>();

                string query = "SELECT LicenseKey, UnencryptedLicenseKey, UserID, IsActive, StartDate, ExpirationDate FROM Licenses";

                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            LicenseInfo license = new LicenseInfo
                            {
                                EncryptedLicenseKey = reader["LicenseKey"].ToString(),
                                UnencryptedLicenseKey = reader["UnencryptedLicenseKey"].ToString(),
                                UserID = reader["UserID"] as int?,
                                IsActive = (bool)reader["IsActive"],
                                StartDate = Convert.IsDBNull(reader["StartDate"]) ? DateTime.MinValue : (DateTime)reader["StartDate"],
                                ExpirationDate = Convert.IsDBNull(reader["ExpirationDate"]) ? DateTime.MinValue : (DateTime)reader["ExpirationDate"]
                            };
                            licenses.Add(license);
                        }
                    }
                }

                return licenses;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while getting all licenses: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred while getting all licenses: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while getting all licenses: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                return null;
            }
        }

        class LicenseInfo
        {
            public string EncryptedLicenseKey { get; set; }
            public string UnencryptedLicenseKey { get; set; }
            public int? UserID { get; set; }
            public bool IsActive { get; set; }
            public DateTime StartDate { get; set; }
            public DateTime ExpirationDate { get; set; }
        }
        //ShowAllLicense

        static void ViewLogs(SqlConnection connection)
        {
            string choice;
            try
            {
                do
                {
                    Console.Clear();
                    Console.Title = "Zyix Auth System - Logs Menu";
                    Console.WriteLine("Logs Menu:");
                    Console.WriteLine("1. View Logs in the Last 48 Hours");
                    Console.WriteLine("2. Clear Logs");
                    Console.WriteLine("3. Back to Admin Menu");
                    Console.Write("Enter your choice: ");
                    choice = Console.ReadLine();

                    switch (choice)
                    {
                        case "1":
                            ViewLogsLast48Hours(connection, loggedInUsername);
                            break;
                        case "2":
                            ClearLogs(connection);
                            break;
                        case "3":
                            AdminMenu(connection);
                            break;
                        default:
                            Console.WriteLine("Invalid choice. Press any key to try again.");
                            Console.ReadKey();
                            break;
                    }
                } while (choice != "3");

            }
            catch (Exception ex)
            {

                Console.WriteLine($"An error occurred in ViewLogs: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int userID = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error"; // 'Error', 'Warning', 'Info'
                    string logDescription = $"An error occurred in ViewLogs: {ex.Message}";
                    logger.LogTransaction(userID, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred in ViewLogs: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
                Console.ReadKey();
            }
        }
        public class LogEntry
        {
            public int LogID { get; set; }
            public string LogLevel { get; set; }
            public string LogDescription { get; set; }
            public DateTime LogDate { get; set; }
            public int UserID { get; set; }
        }

        static void ViewLogsLast48Hours(SqlConnection connection, string loggedInUsername)
        {
            try
            {
                Console.Write("Enter the username to view logs: ");
                string usernameToViewLogs = Console.ReadLine();

                if (!string.IsNullOrEmpty(usernameToViewLogs))
                {
                    int userIdToViewLogs = GetUserId(connection, usernameToViewLogs);

                    if (userIdToViewLogs != -1)
                    {
                        List<LogEntry> logs = GetLogsLast48Hours(connection, userIdToViewLogs);

                        if (logs.Count > 0)
                        {
                            string fileName = $"{usernameToViewLogs}-LogsLast48Hours.txt"; // Dosya adını oluştur

                            using (StreamWriter writer = new StreamWriter(fileName))
                            {
                                foreach (var log in logs)
                                {
                                    writer.WriteLine($"Timestamp: {log.LogDate}");
                                    writer.WriteLine($"Level: {log.LogLevel}");
                                    writer.WriteLine($"Description: {log.LogDescription}");
                                    writer.WriteLine("------------------------------------------------------------------------------------");
                                }
                            }

                            int loggedInUserId = GetUserId(connection, loggedInUsername);
                            Logger logger = new Logger(AppSettings.DbConnectionString);
                            string logLevel = "Info";
                            string logDescription = $"Logs from the last 48 hours for user '{usernameToViewLogs}' have been written to '{fileName}'.";
                            logger.LogTransaction(loggedInUserId, logLevel, logDescription);

                            Console.WriteLine($"Logs from the last 48 hours for user '{usernameToViewLogs}' have been written to '{fileName}'.");
                        }
                        else
                        {
                            Console.WriteLine($"No logs found for user '{usernameToViewLogs}' in the last 48 hours.");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"User '{usernameToViewLogs}' not found.");
                    }
                }
                else
                {
                    Console.WriteLine("Username cannot be empty.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while viewing logs from the last 48 hours: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");
            }

            Console.WriteLine("Press any key to return to the Admin Menu.");
            Console.ReadKey();

        }


        static List<LogEntry> GetLogsLast48Hours(SqlConnection connection, int userId)
        {
            List<LogEntry> logs = new List<LogEntry>();

            try
            {
                if (connection.State == ConnectionState.Closed)
                    connection.Open();

                string query = "SELECT LogID, LogLevel, LogDescription, LogDate, UserID FROM Logs WHERE LogDate >= DATEADD(day, -2, GETDATE()) AND UserID = @UserID";
                using (SqlCommand command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@UserID", userId);
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            LogEntry log = new LogEntry
                            {
                                LogDate = reader.GetDateTime(3),
                                LogLevel = reader.GetString(1),
                                LogDescription = reader.GetString(2)
                            };
                            logs.Add(log);
                        }
                    }
                }
                connection.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while viewing logs from the last 48 hours: {ex.Message}");
                Console.WriteLine("Please contact the software developer for assistance.");

                try
                {
                    int loggedInUserId = GetUserId(connection, loggedInUsername);
                    Logger logger = new Logger(AppSettings.DbConnectionString);
                    string logLevel = "Error";
                    string logDescription = $"An error occurred while viewing logs from the last 48 hours: {ex.Message}";
                    logger.LogTransaction(loggedInUserId, logLevel, logDescription);
                }
                catch (Exception logEx)
                {
                    string userPublicIpAddress = GetPublicIpAddress();
                    FileLogger logger = new FileLogger("Logs.log");
                    logger.LogError($"An error occurred while viewing logs from the last 48 hours: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                }
            }
            return logs;
        }
        static void ClearLogs(SqlConnection connection)
        {
            Console.Write("Enter the username for which you want to clear all logs: ");
            string username = Console.ReadLine();
            if (!string.IsNullOrEmpty(username))
            {
                int userID = GetUserId(connection, username);

                if (userID > 0)
                {
                    try
                    {
                        string deleteQuery = "DELETE FROM Logs WHERE UserID = @UserID";

                        using (SqlCommand command = new SqlCommand(deleteQuery, connection))
                        {
                            command.Parameters.AddWithValue("@UserID", userID);
                            int rowsAffected = command.ExecuteNonQuery();

                            if (rowsAffected > 0)
                            {
                                string userPublicIpAddress = GetPublicIpAddress();
                                FileLogger logger = new FileLogger("Logs.log");
                                logger.LogError($"All logs for user {username} have been cleared.", "Info");
                                Console.WriteLine($"All logs for user {username} have been cleared.");
                            }
                            else
                            {
                                Console.WriteLine($"No logs found for user {username}.");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"An error occurred while clearing logs: {ex.Message}");
                        Console.WriteLine("Please contact the software developer for assistance.");

                        try
                        {
                            int loggedInUserId = GetUserId(connection, loggedInUsername);
                            Logger logger = new Logger(AppSettings.DbConnectionString);
                            string logLevel = "Error";
                            string logDescription = $"An error occurred while clearing logs: {ex.Message}";
                            logger.LogTransaction(loggedInUserId, logLevel, logDescription);
                        }
                        catch (Exception logEx)
                        {
                            string userPublicIpAddress = GetPublicIpAddress();
                            FileLogger logger = new FileLogger("Logs.log");
                            logger.LogError($"An error occurred while clearing logs: {ex.Message}\nAn error occurred logEx: {logEx.Message} User IP: {userPublicIpAddress}", "ERROR");
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"User {username} not found or has no logs.");
                }
            }
            else
            {
                Console.WriteLine("Username cannot be empty.");
            }
            Console.WriteLine("Press any key to return to the Logs Menu.");
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
        static string GenerateRandomLicenseKey()
        {
            const string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            Random random = new Random();
            char[] licenseKeyArray = new char[16];

            for (int i = 0; i < licenseKeyArray.Length; i++)
            {
                licenseKeyArray[i] = characters[random.Next(characters.Length)];
            }

            return new string(licenseKeyArray);
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
        private static string GetSecurityQuestion(int userID, SqlConnection connection)
        {
            string query = "SELECT SecurityQuestion FROM Admins WHERE AdminID = @AdminID";

            using (SqlCommand command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@AdminID", userID);
                return command.ExecuteScalar()?.ToString();
            }
        }
        private static string GetSecurityQuestionAnswer(int userID, SqlConnection connection)
        {
            string query = "SELECT SecurityQuestionAnswer FROM Admins WHERE AdminID = @AdminID";

            using (SqlCommand command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@AdminID", userID);
                return command.ExecuteScalar()?.ToString();
            }
        }
        private static void SaveSecurityQuestion(int userID, string question, SqlConnection connection)
        {
            string query = "UPDATE Admins SET SecurityQuestion = @Question WHERE AdminID = @AdminID";

            using (SqlCommand command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@Question", question);
                command.Parameters.AddWithValue("@AdminID", userID);
                command.ExecuteNonQuery();
            }
        }
        private static void SaveSecurityQuestionAnswer(int userID, string answer, SqlConnection connection)
        {
            string query = "UPDATE Admins SET SecurityQuestionAnswer = @Answer WHERE AdminID = @AdminID";

            using (SqlCommand command = new SqlCommand(query, connection))
            {
                command.Parameters.AddWithValue("@Answer", answer);
                command.Parameters.AddWithValue("@AdminID", userID);
                command.ExecuteNonQuery();
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
    }
}