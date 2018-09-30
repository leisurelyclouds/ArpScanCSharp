using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

namespace ArpScanCSharp
{
    /// <summary>
    /// Resolves MAC addresses from IP addresses using the Address Resolution Protocol (ARP)
    /// </summary>
    public class ArpForIpConflict
    {
        public event EventHandler<ResolvedEventArgs> ResolvedEvent;

        private LibPcapLiveDevice _device;

        /// <summary>
        /// Constructs a new ARP Resolver
        /// </summary>
        /// <param name="device">The network device on which this resolver sends its ARP packets</param>
        public ArpForIpConflict(LibPcapLiveDevice device)
        {
            _device = device;
            if (_device.Addresses.Count > 0)
            {
                // attempt to find an ipv4 address.
                // ARP is ipv4, NDP is used for ipv6
                foreach (var address in _device.Addresses)
                {
                    if (address.Addr.type == Sockaddr.AddressTypes.AF_INET_AF_INET6)
                    {
                        // make sure the address is ipv4
                        if (address.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        {
                            LocalIP = address.Addr.ipAddress;
                            break; // break out of the foreach
                        }
                    }
                }

                // if we can't find either an ipv6 or an ipv4 address use the localhost address
                if (LocalIP == null)
                {
                    LocalIP = IPAddress.Parse("127.0.0.1");
                }
            }

            foreach (var address in _device.Addresses)
            {
                if (address.Addr.type == Sockaddr.AddressTypes.HARDWARE)
                {
                    LocalMAC = address.Addr.hardwareAddress;
                }
            }
        }

        /// <summary>
        /// Timeout for a given call to Resolve()
        /// </summary>
        public TimeSpan Timeout { get; set; } = new TimeSpan(0, 0, 1);

        public IPAddress LocalIP { get; }
        public PhysicalAddress LocalMAC { get; }

        /// <summary>
        /// Resolves the MAC address of the specified IP address
        /// </summary>
        /// <param name="destIP">The IP address to resolve</param>
        /// <param name="localIP">The local IP address from which to send the ARP request, if null the local address will be discovered</param>
        /// <param name="localMAC">The localMAC address to use, if null the local mac will be discovered</param>
        /// <returns>The MAC address that matches to the given IP address or
        /// null if there was a timeout</returns>
        public Task Resolve(Packet request,IPAddress destIPAddress)
        {
            // set a last request time that will trigger sending the
            // arp request immediately
            DateTime lastRequestTime = DateTime.FromBinary(0);

            TimeSpan requestInterval = new TimeSpan(0, 0, 1);

            ARPPacket arpPacket = null;

            // attempt to resolve the address with the current timeout
            var timeoutDateTime = DateTime.Now + Timeout;
            while (DateTime.Now < timeoutDateTime)
            {
                if (requestInterval < (DateTime.Now - lastRequestTime))
                {
                    // inject the packet to the wire
                    _device.SendPacket(request);
                    lastRequestTime = DateTime.Now;
                }

                //read the next packet from the network
                var reply = _device.GetNextPacket();
                if (reply == null)
                {
                    continue;
                }

                // parse the packet
                Packet packet = Packet.ParsePacket(reply.LinkLayerType, reply.Data);

                // is this an arp packet?
                arpPacket = (ARPPacket)packet.Extract(typeof(ARPPacket));
                if (arpPacket == null)
                {
                    continue;
                }

                //if this is the reply we're looking for, stop
                if (arpPacket.SenderProtocolAddress.Equals(destIPAddress))
                {
                    ResolvedEvent?.Invoke(this, new ResolvedEventArgs()
                    {
                        IPAddress = arpPacket.SenderProtocolAddress,
                        PhysicalAddress = arpPacket.SenderHardwareAddress
                    });
                }
            }

            return Task.CompletedTask;
        }

        public void Close()
        {
            // free the device
            _device.Close();
        }

        public Packet BuildRequest(IPAddress destIP) => BuildRequest(destIP,  LocalMAC, LocalIP);

        public void OpenAndApplyFilter()
        {
            //create a "tcpdump" filter for allowing only arp replies to be read
            string arpFilter = "arp and ether dst " + LocalMAC.ToString();

            //open the device with 20ms timeout
            _device.Open(DeviceMode.Promiscuous, 20);

            //set the filter
            _device.Filter = arpFilter;
        }

        private Packet BuildRequest(IPAddress destinationIP,
                                                 PhysicalAddress localMac,
                                                 IPAddress localIP)
        {
            // an arp packet is inside of an ethernet packet
            EthernetPacket ethernetPacket = new EthernetPacket(localMac,
                                                                     PhysicalAddress.Parse("FF-FF-FF-FF-FF-FF"),
                                                                     EthernetPacketType.Arp);
            ARPPacket arpPacket = new ARPPacket(ARPOperation.Request,
                                                           PhysicalAddress.Parse("00-00-00-00-00-00"),
                                                           destinationIP,
                                                           localMac,
                                                           localIP);

            // the arp packet is the payload of the ethernet packet
            ethernetPacket.PayloadPacket = arpPacket;

            return ethernetPacket;
        }
    }
    public class ResolvedEventArgs : EventArgs
    {
        public IPAddress IPAddress { get; set; }

        public PhysicalAddress PhysicalAddress { get; set; }
    }
}
