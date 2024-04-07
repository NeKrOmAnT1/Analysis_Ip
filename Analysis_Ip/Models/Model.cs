using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Analysis_Ip.Models
{
    internal class Model
    {
       public class LogEntry
        {
            public string IPAddress { get; set; }
            public DateTime Time { get; set; }
        }
       public class Arguments
        {
            public string FileLog { get; set; }
            public string FileOutput { get; set; }
            public DateTime TimeStart { get; set; }
            public DateTime TimeEnd { get; set; }
            public string AddressStart { get; set; }
            public int? AddressMask { get; set; }
        }
    }
}
