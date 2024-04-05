using System;
using System.IO;

public class FileLogger
{
    private string filePath;

    public FileLogger(string path)
    {
        filePath = path;
    }

    public void LogError(string message, string logLevel)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                File.Create(filePath).Close();
            }

            File.AppendAllText(filePath, $"{DateTime.Now}: {logLevel} - {message}\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred while logging: {ex.Message}");
        }
    }
}
