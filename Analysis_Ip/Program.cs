using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace Analysis_Ip
{
    class Program
    {
        static void Main(string[] args)
        {
            var arguments = ParseArguments(args);
            if (arguments == null)
            {
                Console.WriteLine("Некорректные аргументы командной строки.");
                return;
            }

            var logEntries = ReadLogEntries(arguments.FileLog);
            if (logEntries == null)
            {
                Console.WriteLine("Ошибка при чтении файла журнала.");
                return;
            }
            

            var filteredLogEntries = FilterLogEntriesByTime(logEntries, arguments.TimeStart, arguments.TimeEnd);
            filteredLogEntries = FilterLogEntriesByAddress(filteredLogEntries, arguments.AddressStart, arguments.AddressMask);
            var ipCounts = CountRequestsByIPAddress(filteredLogEntries);

            WriteResultsToFile(arguments.FileOutput, ipCounts);

            Console.WriteLine("Анализ завершен. Результаты записаны в файл.");
        }

        static Arguments ParseArguments(string[] args)
        {
            if (args.Length < 6)
                return null;

            var result = new Arguments();

            for (int i = 0; i < args.Length; i += 2)
            {
                switch (args[i])
                {
                    case "--file-log":
                        result.FileLog = args[i + 1];
                        break;
                    case "--file-output":
                        result.FileOutput = args[i + 1];
                        break;
                    case "--time-start":
                        result.TimeStart = DateTime.ParseExact(args[i + 1], "dd.MM.yyyy", CultureInfo.InvariantCulture);
                        break;
                    case "--time-end":
                        result.TimeEnd = DateTime.ParseExact(args[i + 1], "dd.MM.yyyy", CultureInfo.InvariantCulture);
                        break;
                    case "--address-start":
                        result.AddressStart = args[i + 1];
                        break;
                    case "--address-mask":
                        result.AddressMask = ParseAddressMask(args[i + 1]);
                        break;
                }
            }
            return result;
        }
        static int? ParseAddressMask(string mask)
        {
            var parts = mask.Split('.');
            if (parts.Length != 4)
                return null;

            try
            {
                var result = 0;
                foreach (var part in parts)
                {
                    int octet = int.Parse(part);
                    if (octet < 0 || octet > 255)
                        return null;
                    result += Convert.ToString(octet, 2).Count(c => c == '1');
                }
                return result;
            }
            catch
            {
                return null;
            }
        }

        static List<LogEntry> ReadLogEntries(string filePath)
        {
            try
            {
                var logEntries = new List<LogEntry>();

                foreach (var line in File.ReadAllLines(filePath))
                {
                    if (!string.IsNullOrWhiteSpace(line))
                    {
                        var parts = line.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length == 3)
                        {
                            if (DateTime.TryParseExact($"{parts[1]} {parts[2]}", "yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime time))
                            {
                                logEntries.Add(new LogEntry { IPAddress = parts[0], Time = time });
                            }
                            else
                            {
                                Console.WriteLine($"Ошибка при чтении строки: {line}. Неверный формат даты и времени.");
                            }
                        }
                        else
                        {
                            Console.WriteLine($"Ошибка при чтении строки: {line}. Неверный формат строки.");
                        }
                    }
                }

                return logEntries;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при чтении файла: {ex.Message}");
                return null;
            }
        }

        static List<LogEntry> FilterLogEntriesByTime(List<LogEntry> logEntries, DateTime startTime, DateTime endTime)
        {
            return logEntries.Where(entry => entry.Time >= startTime && entry.Time <= endTime).ToList();
        }

        static List<LogEntry> FilterLogEntriesByAddress(List<LogEntry> logEntries, string startAddress, int? mask)
        {
            if (startAddress == null)
                return logEntries;

            return logEntries.Where(entry => IsInRange(entry.IPAddress, startAddress, mask)).ToList();
        }

        static bool IsInRange(string ipAddress, string startAddress, int? mask)
        {
            var ipBytes = ipAddress.Split('.').Select(byte.Parse).ToArray();
            var startBytes = startAddress.Split('.').Select(byte.Parse).ToArray();

            if (mask == null || mask > 32 || mask < 0)
                return false;

            var numBytes = mask.Value / 8;
            var remainderBits = mask.Value % 8;

            for (int i = 0; i < numBytes; i++)
            {
                if (ipBytes[i] != startBytes[i])
                    return false;
            }

            if (remainderBits == 0)
                return true;

            var maskByte = (byte)(255 << (8 - remainderBits));

            return (ipBytes[numBytes] & maskByte) == (startBytes[numBytes] & maskByte);
        }

        static Dictionary<string, int> CountRequestsByIPAddress(List<LogEntry> logEntries)
        {
            var counts = new Dictionary<string, int>();

            foreach (var entry in logEntries)
            {
                if (!counts.ContainsKey(entry.IPAddress))
                    counts[entry.IPAddress] = 0;
                counts[entry.IPAddress]++;
            }

            return counts;
        }

        static void WriteResultsToFile(string filePath, Dictionary<string, int> ipCounts)
        {
            try
            {
                using (var writer = new StreamWriter(filePath))
                {
                    foreach (var kvp in ipCounts)
                    {
                        writer.WriteLine($"{kvp.Key}: {kvp.Value}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка при записи в файл: {ex.Message}");
            }
        }
    }

    class LogEntry
    {
        public string IPAddress { get; set; }
        public DateTime Time { get; set; }
    }

    class Arguments
    {
        public string FileLog { get; set; }
        public string FileOutput { get; set; }
        public DateTime TimeStart { get; set; }
        public DateTime TimeEnd { get; set; }
        public string AddressStart { get; set; }
        public int? AddressMask { get; set; }
    }
}
