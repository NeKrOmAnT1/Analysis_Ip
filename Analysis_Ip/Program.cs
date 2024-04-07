using static Analysis_Ip.Methods;

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
    }
}
