using System;
using System.Threading;
using System.Collections.Generic;
using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.IpV6;
using PcapDotNet.Packets.Transport;
using PcapDotNet.Core.Extensions;
using System.Net;
using System.Net.NetworkInformation;
namespace MultiThreading
{
    class Program
    {
        static Dictionary<ushort, Packet> Cevaplar = new Dictionary<ushort, Packet>();
        static MacAddress sourceMAC;
        static MacAddress destinationMAC;
        static string sourceIP_str;
        static IpV4Address sourceIP;
        static IpV4Address destinationIP;
        static LivePacketDevice selectedDevice;
        static Dictionary<ushort, DateTime> pingID = new Dictionary<ushort, DateTime>();
        static int sonSorgu = 0; // max hops


        static void Main(string[] args)
        {

            // Retrieve the device list from the local machine
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;
            // Take the selected adapter
            selectedDevice = allDevices[3];

            sourceMAC = selectedDevice.GetMacAddress(); //PC MAC adresi
            
            destinationMAC = new MacAddress("d4:5d:64:15:a2:f0"); // Default Getway MAC adresi

            sourceIP_str = null;

            foreach (DeviceAddress address in selectedDevice.Addresses)
            {
                if (address.Address.Family == SocketAddressFamily.Internet)
                    sourceIP_str = address.Address.ToString().Substring(9, address.Address.ToString().Length - 9);
            }

            sourceIP = new IpV4Address(sourceIP_str);
            //Console.Write("IP Adresi: ");
            //String dstIP = Console.ReadLine();
            //destinationIP = new IpV4Address(dstIP);
            destinationIP = new IpV4Address("8.8.4.4");
            Thread thread1 = new Thread(Ping);
            Thread thread2 = new Thread(Dinle);

            thread1.Start();
            thread2.Start();


            Console.WriteLine("Traceroute : " + destinationIP);
            Console.WriteLine("Yapacagi Sicrama Sayisi : 15" + "\n");
            Console.WriteLine("Sutun \t" + "Sure \t" + "\t IP   [Host Name]");
        }

        private static void Ping()
        {
            // Open the output device
            using (PacketCommunicator communicator = selectedDevice.Open(100, // name of the device
                                                                         PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                                                         1000)) // read timeout
            {
                for (ushort i = 1; i < 15; i++) // 15 TTL sonucu paket gönderimi sonlanacak
                {
                    if (sonSorgu == 15)
                    {
                        
                        break;
                    }
                    // her paketin özel oması için ve TTL değerini belirlemek için "i" gönderdik
                    var paketveID = BuildIcmpPacket(i, i, i); 
                    //Console.WriteLine(paketveID.Item2.ToString());
                    pingID.Add(i, DateTime.Now);
                    communicator.SendPacket(paketveID.Item1);

                    var t = new Thread(() => Yorumla(i));
                    t.Start();
                    
                    Thread.Sleep(2000);
                    

                }
            }

        }
        private static Tuple<Packet, ushort> BuildIcmpPacket(ushort ID, ushort Identifier, ushort yeniTTL)
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = sourceMAC,
                    Destination = destinationMAC,
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = sourceIP,
                    CurrentDestination = destinationIP,
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = Identifier,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = Convert.ToByte(yeniTTL),
                    TypeOfService = 0,
                };


            IcmpEchoLayer icmpLayer =
                new IcmpEchoLayer
                {
                    Checksum = null, // Will be filled automatically.
                    Identifier = ID,
                    SequenceNumber = 800,
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, icmpLayer);

            return Tuple.Create(builder.Build(DateTime.Now), ID); // olusturulan Tuple'a zaman ve ID ataniyor

        }
        static void Dinle()
        {

            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                            // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                // Compile the filter
                using (BerkeleyPacketFilter filter = communicator.CreateFilter("icmp and ip and dst " + sourceIP.ToString())) //
                {
                    // Set the filter
                    communicator.SetFilter(filter);
                }
                

                // Retrieve the packets
                Packet p;
                do
                {
                    PacketCommunicatorReceiveResult result = communicator.ReceivePacket(out p);
                    switch (result)
                    {
                        case PacketCommunicatorReceiveResult.Timeout:
                            // Timeout elapsed
                            continue;
                        case PacketCommunicatorReceiveResult.Ok:
                            IpV4Datagram ip = p.Ethernet.IpV4;
                            IcmpDatagram icmp = ip.Icmp;
                            string sonuc = icmp.ToHexadecimalString();
                            
                            ushort ID;

                            //  EchoReply ve TimeExceeded mesajlarinin boyutlu farkli oldugu icin
                            //  bu sorgu yapilir ve hexnumber Parse metodu ile ushort'a cevrilir
                            if (icmp.MessageType == IcmpMessageType.EchoReply)
                            {
                                 ID = ushort.Parse(sonuc.Substring(8, 4), System.Globalization.NumberStyles.HexNumber);
                            }
                            else 
                            {
                                
                                ID = ushort.Parse(sonuc.Substring(64, 4), System.Globalization.NumberStyles.HexNumber);
                            }
                            

                            lock (Cevaplar)
                            {
                                Cevaplar.Add(ID, p);
                            }
                            break;
                        default:
                            throw new InvalidOperationException("The result " + result + " should never be reached here");
                    }
                } while (true);
            }
        }

        static void Yorumla(ushort ID)
        {
            sonSorgu++;
            Thread.Sleep(3000); // 2.5 saniye bekle sonra gelen cevaplara bak. Cevap yoksa, zaman asimi.
            Packet p;
            try
            {
                lock (Cevaplar)
                {
                    p = Cevaplar[ID];
                }
            }
            catch
            {
                Console.WriteLine("***"); // Zaman asimi
                return;
            }
            DateTime almazamani = p.Timestamp;
            

            IpV4Datagram ip = p.Ethernet.IpV4;
            IcmpDatagram icmp = ip.Icmp;

            if (icmp.MessageType == IcmpMessageType.DestinationUnreachable)
                Console.WriteLine("Hedefe ulasilamiyor");
            else if (icmp.MessageType == IcmpMessageType.EchoReply)
            {

                /*  
                    Eger gelen mesaj EchoReply ise son adrese ulasilmis demektir
                    Son adrese ulastigimiz icin artik donguyu iptal edebiliriz
                 */

                sonSorgu = 15; 
                                
                DateTime gondermezamani = pingID[ID];
                double zaman = (almazamani - gondermezamani).TotalMilliseconds;
                var sourceHostName = "[" + Dns.GetHostEntry(IPAddress.Parse(ip.Source.ToString())).HostName + "]";
                Console.WriteLine(ID +"\t" + zaman.ToString() + " ms" + "\t" + ip.Source.ToString() + sourceHostName);
                Console.WriteLine("Trace Tamamlandi");


            }
            else if (icmp.MessageType == IcmpMessageType.TimeExceeded)
            {
                DateTime gondermezamani = pingID[ID];
                double zaman = (almazamani - gondermezamani).TotalMilliseconds;
                /*
                    Gelen mesajin hangi ag elemanindan dondugunu ogreniriz
                    Bazi ag elemanlarinin isimlerine ulasamadigimiz icin try-catch icinde kulandik
                    Try-catch işlemi zaman aşımı yaratabiliyor
                 */
                /*
                var sourceHostName = "";
                try {
                    sourceHostName = "["+Dns.GetHostEntry(IPAddress.Parse(ip.Source.ToString())).HostName+"]";
                }
                catch
                {
                    sourceHostName = "";
                }
                */
                
                //  + sourceHostName 
                

                Console.WriteLine(ID +"\t" + zaman.ToString() + " ms" + "\t" + ip.Source.ToString()  );
                
            }

        }
    }
}