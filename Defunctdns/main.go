package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	typeA    = 1
	typeSOA  = 6
	typeAAAA = 28
	classIN  = 1
)

type dnsQuestion struct {
	Name   string
	Qtype  uint16
	Qclass uint16
}

func main() {
	port := flag.Int("port", 53, "UDP listen port")
	includeSOA := flag.Bool("soa", false, "include SOA record on AAAA queries")
	fixAAAA := flag.Bool("fix", false, "return NOERROR with empty answers on AAAA for existing names")
	logRequests := flag.Bool("log", false, "log DNS requests")
	flag.Parse()

	records, err := loadRecords()
	if err != nil {
		log.Printf("records: %v", err)
	}

	addr := fmt.Sprintf(":%d", *port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer conn.Close()

	log.Printf("listening on %s", addr)

	buf := make([]byte, 1500)
	for {
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("read: %v", err)
			continue
		}

		req := make([]byte, n)
		copy(req, buf[:n])

		resp, err := handleQuery(req, records, *includeSOA, *fixAAAA, *logRequests)
		if err != nil {
			log.Printf("handle: %v", err)
			continue
		}

		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.WriteTo(resp, clientAddr); err != nil {
			log.Printf("write: %v", err)
		}
	}
}

func handleQuery(req []byte, records map[string]net.IP, soaOnAAAA bool, fixAAAA bool, logRequests bool) ([]byte, error) {
	if len(req) < 12 {
		return nil, fmt.Errorf("short header")
	}

	id := binary.BigEndian.Uint16(req[0:2])
	flags := binary.BigEndian.Uint16(req[2:4])
	qdCount := binary.BigEndian.Uint16(req[4:6])

	if qdCount == 0 {
		return nil, fmt.Errorf("no question")
	}

	_, _, _, rcode := parseFlags(flags)
	if rcode != 0 {
		return nil, fmt.Errorf("query has rcode %d", rcode)
	}

	q, _, err := parseQuestion(req, 12)
	if err != nil {
		return nil, err
	}

	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	ip, match := records[name]
	responseCode := uint16(0)
	answerIP := net.IP(nil)
	includeSOA := false

	if logRequests {
		log.Printf("query name=%s type=%s class=%d", name, qtypeString(q.Qtype), q.Qclass)
	}

	if match && q.Qtype == typeA {
		answerIP = ip.To4()
		if answerIP == nil {
			match = false
			responseCode = 3
		}
	}

	if q.Qtype == typeAAAA {
		if match && fixAAAA {
			responseCode = 0 // NOERROR, empty answer (NODATA)
			includeSOA = false
		} else {
			responseCode = 3 // NXDOMAIN
			includeSOA = soaOnAAAA
		}
	}
	if !match {
		responseCode = 3
	}

	resp := buildResponse(id, q, answerIP, includeSOA, responseCode)
	return resp, nil
}

func buildResponse(id uint16, q dnsQuestion, answerIP net.IP, includeSOA bool, rcode uint16) []byte {
	var buf bytes.Buffer

	qdCount := uint16(1)
	anCount := uint16(0)
	if answerIP != nil {
		anCount = 1
	}
	nsCount := uint16(0)
	if includeSOA {
		nsCount = 1
	}

	flags := buildFlags(true, true, rcode)
	_ = binary.Write(&buf, binary.BigEndian, id)
	_ = binary.Write(&buf, binary.BigEndian, flags)
	_ = binary.Write(&buf, binary.BigEndian, qdCount)
	_ = binary.Write(&buf, binary.BigEndian, anCount)
	_ = binary.Write(&buf, binary.BigEndian, nsCount)
	_ = binary.Write(&buf, binary.BigEndian, uint16(0)) // ARCOUNT

	qname := encodeName(q.Name)
	buf.Write(qname)
	_ = binary.Write(&buf, binary.BigEndian, q.Qtype)
	_ = binary.Write(&buf, binary.BigEndian, q.Qclass)

	if answerIP != nil {
		// Answer name: pointer to question name at offset 12 (0x0c)
		buf.Write([]byte{0xC0, 0x0C})
		_ = binary.Write(&buf, binary.BigEndian, uint16(typeA))
		_ = binary.Write(&buf, binary.BigEndian, uint16(classIN))
		_ = binary.Write(&buf, binary.BigEndian, uint32(300)) // TTL
		_ = binary.Write(&buf, binary.BigEndian, uint16(4))   // RDLENGTH
		buf.Write(answerIP)
	}

	if includeSOA {
		soaRdata := buildSOARdata()
		buf.Write(encodeName("."))
		_ = binary.Write(&buf, binary.BigEndian, uint16(typeSOA))
		_ = binary.Write(&buf, binary.BigEndian, uint16(classIN))
		_ = binary.Write(&buf, binary.BigEndian, uint32(300))           // TTL
		_ = binary.Write(&buf, binary.BigEndian, uint16(len(soaRdata))) // RDLENGTH
		_, _ = buf.Write(soaRdata)
	}

	return buf.Bytes()
}

func loadRecords() (map[string]net.IP, error) {
	recordsPath := filepath.Join(".", "records.txt")
	data, err := os.ReadFile(recordsPath)
	if err != nil {
		if os.IsNotExist(err) {
			dummy := "# records.txt: one record per line as \"name ip\"\n" +
				"# Example:\n" +
				"# test.local 10.10.10.10\n" +
				"test.local 10.10.10.10\n"
			if writeErr := os.WriteFile(recordsPath, []byte(dummy), 0644); writeErr != nil {
				return map[string]net.IP{}, fmt.Errorf("create records.txt: %w", writeErr)
			}
			return map[string]net.IP{
				"test.local": net.ParseIP("10.10.10.10").To4(),
			}, nil
		}
		return map[string]net.IP{}, err
	}

	records := make(map[string]net.IP)
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			log.Printf("records.txt line %d: expected \"name ip\"", i+1)
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(fields[0]), ".")
		ip := net.ParseIP(fields[1]).To4()
		if ip == nil {
			log.Printf("records.txt line %d: invalid IPv4 %q", i+1, fields[1])
			continue
		}
		records[name] = ip
	}

	return records, nil
}

func qtypeString(qtype uint16) string {
	switch qtype {
	case typeA:
		return "A"
	case typeAAAA:
		return "AAAA"
	case typeSOA:
		return "SOA"
	default:
		return fmt.Sprintf("TYPE%d", qtype)
	}
}

func buildSOARdata() []byte {
	var buf bytes.Buffer
	buf.Write(encodeName("a.root-servers.net."))
	buf.Write(encodeName("nstld.verisign-grs.com."))
	_ = binary.Write(&buf, binary.BigEndian, uint32(2025121900)) // SERIAL
	_ = binary.Write(&buf, binary.BigEndian, uint32(1800))       // REFRESH
	_ = binary.Write(&buf, binary.BigEndian, uint32(900))        // RETRY
	_ = binary.Write(&buf, binary.BigEndian, uint32(604800))     // EXPIRE
	_ = binary.Write(&buf, binary.BigEndian, uint32(86400))      // MINIMUM
	return buf.Bytes()
}

func parseQuestion(msg []byte, offset int) (dnsQuestion, int, error) {
	name, off, err := readName(msg, offset)
	if err != nil {
		return dnsQuestion{}, 0, err
	}
	if off+4 > len(msg) {
		return dnsQuestion{}, 0, fmt.Errorf("short question")
	}
	qtype := binary.BigEndian.Uint16(msg[off : off+2])
	qclass := binary.BigEndian.Uint16(msg[off+2 : off+4])
	return dnsQuestion{Name: name, Qtype: qtype, Qclass: qclass}, off + 4, nil
}

func readName(msg []byte, offset int) (string, int, error) {
	var labels []string
	start := offset
	jumped := false
	for {
		if offset >= len(msg) {
			return "", 0, fmt.Errorf("name out of bounds")
		}
		length := msg[offset]
		if length == 0 {
			offset++
			break
		}
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(msg) {
				return "", 0, fmt.Errorf("pointer out of bounds")
			}
			ptr := int(length&^0xC0)<<8 | int(msg[offset+1])
			if ptr >= len(msg) {
				return "", 0, fmt.Errorf("bad pointer")
			}
			if !jumped {
				start = offset + 2
				jumped = true
			}
			offset = ptr
			continue
		}
		offset++
		if offset+int(length) > len(msg) {
			return "", 0, fmt.Errorf("label out of bounds")
		}
		labels = append(labels, string(msg[offset:offset+int(length)]))
		offset += int(length)
	}
	name := strings.Join(labels, ".")
	if jumped {
		return name, start, nil
	}
	return name, offset, nil
}

func encodeName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}
	}
	labels := strings.Split(name, ".")
	var buf bytes.Buffer
	for _, label := range labels {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	return buf.Bytes()
}

func parseFlags(flags uint16) (qr bool, aa bool, opcode uint16, rcode uint16) {
	qr = (flags>>15)&1 == 1
	opcode = (flags >> 11) & 0xF
	aa = (flags>>10)&1 == 1
	rcode = flags & 0xF
	return
}

func buildFlags(qr bool, aa bool, rcode uint16) uint16 {
	var flags uint16
	if qr {
		flags |= 1 << 15
	}
	if aa {
		flags |= 1 << 10
	}
	flags |= rcode & 0xF
	return flags
}
