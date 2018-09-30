using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;
using MacAddressVendorLookup;
using System.IO;

namespace ArpScanCSharp
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            // Retrieve the device list
            var devices = LibPcapLiveDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
                return;
            }

            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            int i = 0;

            // Print out the available devices
            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                foreach (var address in dev.Addresses)
                {
                    Console.WriteLine($"{address}");
                }
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device for sending the ARP request: ");
            i = int.Parse(Console.ReadLine());

            var device = devices[i];
            IPAddress startIPAddress;
            IPAddress stopIPAddress;

            // loop until a valid ip address is parsed
            while (true)
            {
                Console.Write("-- Please enter Start IP address to be resolved by ARP: ");
                if (IPAddress.TryParse(Console.ReadLine(), out startIPAddress))
                {
                    break;
                }

                Console.WriteLine("Bad IP address format, please try again");
            }
            // loop until a valid ip address is parsed
            while (true)
            {
                Console.Write("-- Please enter Stop IP address to be resolved by ARP: ");
                if (System.Net.IPAddress.TryParse(Console.ReadLine(), out stopIPAddress))
                {
                    break;
                }

                Console.WriteLine("Bad IP address format, please try again");
            }
            ArpForIpConflict arper = new ArpForIpConflict(device);
            arper.ResolvedEvent += ArpForIpConflict_ResolvedEvent;

            var ipAddresses = GenerateIPAddresses(startIPAddress, stopIPAddress);
            List<Task> resolveTasks = new List<Task>();
            arper.OpenAndApplyFilter();
            foreach (var ipAddress in ipAddresses)
            {
                var request = arper.BuildRequest(ipAddress);
                arper.Resolve(request, ipAddress);
            }
            arper.Close();
            Console.WriteLine("Exit Scan");

            Console.WriteLine("Print Result");
            var IPAddressPhysicalAddressLookup = IPAddressPhysicalAddressMapList.ToLookup(l => l.iPAddress, l => l.physicalAddress).Where(lu => lu.Count() > 1);
            var reader = new WiresharkManufReader();
            using (var manufTxtFile = File.OpenRead("manuf.txt"))
            {
                reader.Init(manufTxtFile).Wait();
            }
            var addressMatcher = new AddressMatcher(reader);

            Console.ForegroundColor = ConsoleColor.Red;
            // Iterate through each IGrouping in the Lookup and output the contents.
            foreach (var IPAddressPhysicalAddressGroup in IPAddressPhysicalAddressLookup)
            {
                // Print the key value of the IGrouping.
                Console.WriteLine($"IP:{IPAddressPhysicalAddressGroup.Key}");
                // Iterate through each value in the IGrouping and print its value.
                foreach (var physicalAddress in IPAddressPhysicalAddressGroup)
                {
                    var vendorInfo = addressMatcher.FindInfo(physicalAddress);
                    if (vendorInfo != null)
                    {
                        Console.WriteLine($"\t{physicalAddress}\t{vendorInfo.Organization}");
                    }
                    else
                    {
                        Console.WriteLine($"\t{physicalAddress}");
                    }
                }
            }
            Console.ForegroundColor = ConsoleColor.White;

            Console.WriteLine("Press Enter To Exit");
            Console.ReadLine();
        }

        private static List<IPAddress> GenerateIPAddresses(IPAddress startIPAddress, IPAddress stopIPAddress)
        {
            List<IPAddress> ipAddresses = new List<IPAddress>();
            var currentAddress = startIPAddress;
            while (!currentAddress.GetAddressBytes().SequenceEqual(stopIPAddress.GetAddressBytes()))
            {
                ipAddresses.Add(currentAddress);
                currentAddress = AddOne(currentAddress);
            }
            return ipAddresses;
        }

        private static List<(IPAddress iPAddress, PhysicalAddress physicalAddress)> IPAddressPhysicalAddressMapList = new List<(IPAddress iPAddress, PhysicalAddress physicalAddress)>();

        private static IPAddress AddOne(IPAddress iPAddress)
        {
            byte[] IPAddressBytes = iPAddress.GetAddressBytes();
            int i = IPAddressBytes.Length - 1;
            while (i >= 0)
            {
                if (IPAddressBytes[i] == 255)
                {
                    IPAddressBytes[i] = 0;
                    i--;
                }
                else
                {
                    IPAddressBytes[i]++;
                    break;
                }
            }
            return new IPAddress(IPAddressBytes);
        }
        private static void ArpForIpConflict_ResolvedEvent(object sender, ResolvedEventArgs e) => IPAddressPhysicalAddressMapList.Add((e.IPAddress, e.PhysicalAddress));
    }
}
