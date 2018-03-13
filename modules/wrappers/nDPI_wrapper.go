package wrappers

// #include "wrappers_config.h"
// #cgo CFLAGS: -I/usr/local/include/
// #cgo LDFLAGS: -Wl,-Bstatic -lndpi -Wl,-Bdynamic -lpcap -lm -pthread
// #include "nDPI_wrapper_impl.h"
import "C"
import (
	"unsafe"

	"github.com/google/gopacket"
	"github.com/hamidrezabstn/go-dpi/types"
	"github.com/pkg/errors"
)

// ndpiCodeToProtocol maps the nDPI protocol codes to go-dpi protocols.
var ndpiCodeToProtocol = map[uint32]types.Protocol{	
	//2: types.SIZE,
	0: types.UNKNOWN,
	1: types.FTP_CONTROL, /* Tomasz Bujlow <tomasz@skatnet.dk> */
	2: types.MAIL_POP,
	3: types.MAIL_SMTP,
	4: types.MAIL_IMAP,
	5: types.DNS,
	6: types.IPP,
	7: types.HTTP,
	8: types.MDNS,
	9: types.NTP,
	10: types.NETBIOS,
	11: types.NFS,
	12: types.SSDP,
	13: types.BGP,
	14: types.SNMP,
	15: types.XDMCP,
	16: types.SMB,
	17: types.SYSLOG,
	18: types.DHCP,
	19: types.POSTGRES,
	20: types.MYSQL,
	21: types.HOTMAIL,
	22: types.DIRECT_DOWNLOAD_LINK,
	23: types.MAIL_POPS,
	24: types.APPLEJUICE,
	25: types.DIRECTCONNECT,
	26: types.SOCRATES,
	27: types.COAP,
	28: types.VMWARE,
	29: types.MAIL_SMTPS,
	30: types.FILETOPIA,
	31: types.UBNTAC2, /* Ubiquity UBNT AirControl 2 - Thomas Fjellstrom <thomas+ndpi@fjellstrom.ca> */
	32: types.KONTIKI,
	33: types.OPENFT,
	34: types.FASTTRACK,
	35: types.GNUTELLA,
	36: types.EDONKEY, /* Tomasz Bujlow <tomasz@skatnet.dk> */
	37: types.BITTORRENT,
	38: types.EPP,
	39: types.AVI,
	40: types.FLASH,
	41: types.OGG,
	42: types.MPEG,
	43: types.QUICKTIME,
	44: types.REALMEDIA,
	45: types.WINDOWSMEDIA,
	46: types.MMS,
	47: types.XBOX,
	48: types.QQ,
	49: types.MOVE,
	50: types.RTSP,
	51: types.MAIL_IMAPS,
	52: types.ICECAST,
	53: types.PPLIVE, /* Tomasz Bujlow <tomasz@skatnet.dk> */
	54: types.PPSTREAM,
	55: types.ZATTOO,
	56: types.SHOUTCAST,
	57: types.SOPCAST,
	58: types.TVANTS,
	59: types.TVUPLAYER,
	60: types.HTTP_DOWNLOAD,
	61: types.QQLIVE,
	62: types.THUNDER,
	63: types.SOULSEEK,
	64: types.SSL_NO_CERT,
	65: types.IRC,
	66: types.AYIYA,
	67: types.UNENCRYPTED_JABBER,
	68: types.MSN,
	69: types.OSCAR,
	70: types.YAHOO,
	71: types.BATTLEFIELD,
	72: types.GOOGLE_PLUS,
	73: types.IP_VRRP,
	74: types.STEAM, /* Tomasz Bujlow <tomasz@skatnet.dk> */
	75: types.HALFLIFE2,
	76: types.WORLDOFWARCRAFT,
	77: types.TELNET,
	78: types.STUN,
	79: types.IP_IPSEC,
	80: types.IP_GRE,
	81: types.IP_ICMP,
	82: types.IP_IGMP,
	83: types.IP_EGP,
	84: types.IP_SCTP,
	85: types.IP_OSPF,
	86: types.IP_IP_IN_IP,
	87: types.RTP,
	88: types.RDP,
	89: types.VNC,
	90: types.PCANYWHERE,
	91: types.SSL,
	92: types.SSH,
	93: types.USENET,
	94: types.MGCP,
	95: types.IAX,
	96: types.TFTP,
	97: types.AFP,
	98: types.STEALTHNET,
	99: types.AIMINI,
	100: types.SIP,
	101: types.TRUPHONE,
	102: types.IP_ICMPV6,
	103: types.DHCPV6,
	104: types.ARMAGETRON,
	105: types.CROSSFIRE,
	106: types.DOFUS,
	107: types.FIESTA,
	108: types.FLORENSIA,
	109: types.GUILDWARS,
	110: types.HTTP_APPLICATION_ACTIVESYNC, /*avoid large declarations in the future*/
	111: types.KERBEROS,
	112: types.LDAP,
	113: types.MAPLESTORY,
	114: types.MSSQL_TDS,
	115: types.PPTP,
	116: types.WARCRAFT3,
	117: types.WORLD_OF_KUNG_FU,
	118: types.SLACK,
	119: types.FACEBOOK,
	120: types.TWITTER,
	121: types.DROPBOX,
	122: types.GMAIL,
	123: types.GOOGLE_MAPS,
	124: types.YOUTUBE,
	125: types.SKYPE,
	126: types.GOOGLE,
	127: types.DCERPC,
	128: types.NETFLOW,
	129: types.SFLOW,
	130: types.HTTP_CONNECT,
	131: types.HTTP_PROXY,
	132: types.CITRIX,
	133: types.NETFLIX,
	134: types.LASTFM,
	135: types.WAZE,
	136: types.YOUTUBE_UPLOAD, /* Upload files to youtube */
	137: types.ICQ,
	138: types.CHECKMK,
	139: types.CITRIX_ONLINE,
	140: types.APPLE,
	141: types.WEBEX,
	142: types.WHATSAPP,
	143: types.APPLE_ICLOUD,
	144: types.VIBER,
	145: types.APPLE_ITUNES,
	146: types.RADIUS,
	147: types.WINDOWS_UPDATE,
	148: types.TEAMVIEWER, /* xplico.org */
	149: types.TUENTI,
	150: types.LOTUS_NOTES,
	151: types.SAP,
	152: types.GTP,
	153: types.UPNP,
	154: types.LLMNR,
	155: types.REMOTE_SCAN,
	156: types.SPOTIFY,
	157: types.WEBM,
	158: types.H323, /* Remy Mudingay <mudingay@ill.fr> */
	159: types.OPENVPN, /* Remy Mudingay <mudingay@ill.fr> */
	160: types.NOE, /* Remy Mudingay <mudingay@ill.fr> */
	161: types.CISCOVPN, /* Remy Mudingay <mudingay@ill.fr> */
	162: types.TEAMSPEAK, /* Remy Mudingay <mudingay@ill.fr> */
	163: types.TOR, /* Remy Mudingay <mudingay@ill.fr> */
	164: types.SKINNY, /* Remy Mudingay <mudingay@ill.fr> */
	165: types.RTCP, /* Remy Mudingay <mudingay@ill.fr> */
	166: types.RSYNC, /* Remy Mudingay <mudingay@ill.fr> */
	167: types.ORACLE, /* Remy Mudingay <mudingay@ill.fr> */
	168: types.CORBA, /* Remy Mudingay <mudingay@ill.fr> */
	169: types.UBUNTUONE, /* Remy Mudingay <mudingay@ill.fr> */
	170: types.WHOIS_DAS,
	171: types.COLLECTD,
	172: types.SOCKS, /* Tomasz Bujlow <tomasz@skatnet.dk> */
	173: types.NINTENDO,
	174: types.RTMP, /* Tomasz Bujlow <tomasz@skatnet.dk> */
	175: types.FTP_DATA, /* Tomasz Bujlow <tomasz@skatnet.dk> */
	176: types.WIKIPEDIA, /* Tomasz Bujlow <tomasz@skatnet.dk> */
	177: types.ZMQ,
	178: types.AMAZON, /* Tomasz Bujlow <tomasz@skatnet.dk> */
	179: types.EBAY, /* Tomasz Bujlow <tomasz@skatnet.dk> */
	180: types.CNN, /* Tomasz Bujlow <tomasz@skatnet.dk> */
	181: types.MEGACO, /* Gianluca Costa <g.costa@xplico.org> */
	182: types.REDIS,
	183: types.PANDO, /* Tomasz Bujlow <tomasz@skatnet.dk> */
	184: types.VHUA,
	185: types.TELEGRAM, /* Gianluca Costa <g.costa@xplico.org> */
	186: types.VEVO,
	187: types.PANDORA,
	188: types.QUIC, /* Andrea Buscarinu <andrea.buscarinu@gmail.com> - Michele Campus <michelecampus5@gmail.com> */
	189: types.WHATSAPP_VOICE,
	190: types.EAQ,
	191: types.OOKLA,
	192: types.AMQP,
	193: types.KAKAOTALK, /* KakaoTalk Chat (no voice call) */
	194: types.KAKAOTALK_VOICE, /* KakaoTalk Voice */
	195: types.TWITCH, /* Edoardo Dominici <edoaramis@gmail.com> */
	196: types.QUICKPLAY, /* Streaming service used by various services such as hooq.tv */
	197: types.WECHAT,
	198: types.MPEGTS,
	199: types.SNAPCHAT,
	200: types.SINA,
	201: types.HANGOUT,
	202: types.IFLIX, /* www.vizuamatix.com R&D team & M.Mallawaarachchie <manoj_ws@yahoo.com> */
	203: types.GITHUB,
	204: types.BJNP,
	205: types.ONEKXUN,
	206: types.IQIYI,
	207: types.SMPP, /* Damir Franusic <df@release14.org> */
	208: types.DNSCRYPT,
	209: types.TINC, /* William Guglielmo <william@deselmo.com> */
	210: types.DEEZER,
	211: types.INSTAGRAM, /* Andrea Buscarinu <andrea.buscarinu@gmail.com> */
	212: types.MICROSOFT,
	213: types.STARCRAFT, /* Matteo Bracci <matteobracci1@gmail.com> */
	214: types.TEREDO,
	215: types.HOTSPOT_SHIELD,
	216: types.HEP, /* sipcapture.org QXIP BV */
	217: types.GOOGLE_DRIVE,
	218: types.OCS,
	219: types.OFFICE_365,
	220: types.CLOUDFLARE,
	221: types.MS_ONE_DRIVE,
	222: types.MQTT,
	223: types.RX,
	224: types.APPLESTORE,
	225: types.OPENDNS,
	226: types.GIT,
	227: types.DRDA,
	228: types.PLAYSTORE,
	229: types.SOMEIP,
	230: types.FIX,
	231: types.PLAYSTATION,
	232: types.PASTEBIN, /* Paulo Angelo <pa@pauloangelo.com> */
	233: types.LINKEDIN, /* Paulo Angelo <pa@pauloangelo.com> */
	234: types.SOUNDCLOUD,
	235: types.CSGO, /* Counter-Strike Global Offensive, Dota 2 */
	236: types.LISP,
	237: types.DIAMETER,
	238: types.APPLE_PUSH,
	239: types.GOOGLE_SERVICES,
	240: types.AMAZON_VIDEO,
	241: types.GOOGLE_DOCS,
	242: types.WHATSAPP_FILES, /* Videos, pictures, voice messages... */
}

// NDPIWrapperName is the identification of the nDPI library.
const NDPIWrapperName = "nDPI"

// NDPIWrapperProvider provides NDPIWrapper with the implementations of the
// methods to use.
type NDPIWrapperProvider struct {
	ndpiInitialize    func() int32
	ndpiDestroy       func()
	ndpiPacketProcess func(gopacket.Packet, unsafe.Pointer) []int32
	ndpiAllocFlow     func(gopacket.Packet) unsafe.Pointer
	ndpiFreeFlow      func(unsafe.Pointer)
}

// NDPIWrapper is the wrapper for the nDPI deep inspection library,
// providing the methods used to interface with it from go-dpi.
type NDPIWrapper struct {
	provider *NDPIWrapperProvider
}

// getPacketNdpiData is a helper that extracts the PCAP packet header and packet
// data pointer from a gopacket.Packet, as needed by nDPI.
func getPacketNdpiData(packet gopacket.Packet) (pktHeader C.struct_pcap_pkthdr, pktDataPtr *C.u_char) {
	seconds := packet.Metadata().Timestamp.Second()
	capLen := packet.Metadata().CaptureLength
	packetLen := packet.Metadata().Length
	pktDataSlice := packet.Data()
	pktHeader.ts.tv_sec = C.__time_t(seconds)
	pktHeader.ts.tv_usec = 0
	pktHeader.caplen = C.bpf_u_int32(capLen)
	pktHeader.len = C.bpf_u_int32(packetLen)
	pktDataPtr = (*C.u_char)(unsafe.Pointer(&pktDataSlice[0]))
	return
}

// NewNDPIWrapper constructs an NDPIWrapper with the default implementation
// for its methods.
func NewNDPIWrapper() *NDPIWrapper {
	return &NDPIWrapper{
		provider: &NDPIWrapperProvider{
			ndpiInitialize: func() int32 { return int32(C.ndpiInitialize()) },
			ndpiDestroy:    func() { C.ndpiDestroy() },
			ndpiPacketProcess: func(packet gopacket.Packet, ndpiFlow unsafe.Pointer) []int32 {
				pktHeader, pktDataPtr := getPacketNdpiData(packet)
				result:= make([]int32,2)
				var protos *C.u_int16_t = C.ndpiPacketProcess(&pktHeader, pktDataPtr, ndpiFlow)				
				//convert c array to go slice
				slice := (*[1 << 30]C.u_int16_t)(unsafe.Pointer(protos))[:2:2]				
				result[0] = int32(slice[0])
				result[1] = int32(slice[1])			
				
				return result
			},
			ndpiAllocFlow: func(packet gopacket.Packet) unsafe.Pointer {
				pktHeader, pktDataPtr := getPacketNdpiData(packet)
				return C.ndpiGetFlow(&pktHeader, pktDataPtr)
			},
			ndpiFreeFlow: func(ndpiFlow unsafe.Pointer) {
				C.ndpiFreeFlow(ndpiFlow)
			},
		},
	}
}

// InitializeWrapper initializes the nDPI wrapper.
func (wrapper *NDPIWrapper) InitializeWrapper() int {
	return int((*wrapper.provider).ndpiInitialize())
}

// DestroyWrapper destroys the nDPI wrapper.
func (wrapper *NDPIWrapper) DestroyWrapper() error {
	(*wrapper.provider).ndpiDestroy()
	return nil
}

// ClassifyFlow classifies a flow using the nDPI library. It returns the
// detected protocol and any error.
func (wrapper *NDPIWrapper) ClassifyFlow(flow *types.Flow) ([]types.Protocol, error) {
	packets := flow.GetPackets()
	result := []types.Protocol{types.Unknown,types.Unknown}
	var err error
	if len(packets) > 0 {
		ndpiFlow := (*wrapper.provider).ndpiAllocFlow(packets[0])
		defer (*wrapper.provider).ndpiFreeFlow(ndpiFlow)
		for _, ppacket := range packets {
			ndpiProto := (*wrapper.provider).ndpiPacketProcess(ppacket, ndpiFlow)			
			for i,dproto:= range ndpiProto{
			if proto, found := ndpiCodeToProtocol[uint32(dproto)]; found {
				//log.Println(proto)
				result[i]= proto
			} else if dproto < 0 {
				switch dproto {
				case -10:
					result[i]= types.Unknown
					err = errors.New("nDPI wrapper does not support IPv6")
				case -11:
					result[i]= types.Unknown
					err = errors.New("Received fragmented packet")
				case -12:
					result[i]= types.Unknown
					err = errors.New("Error creating nDPI flow")
				default:
					result[i]= types.Unknown
					err = errors.New("nDPI unknown error")
				}
			}
		}
	}
	}
	return result,err
}

// GetWrapperName returns the name of the wrapper, in order to identify which
// wrapper provided a classification.
func (wrapper *NDPIWrapper) GetWrapperName() types.ClassificationSource {
	return NDPIWrapperName
}
