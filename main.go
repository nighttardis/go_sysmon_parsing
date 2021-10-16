package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	sysmon "github.com/nighttardis/go_sysmon_parsing/sysmon"
)

const MESSAGE = "Oct 15 19:41:27 lsys sysmon: <Event><System><Provider Name=\"Linux-Sysmon\" Guid=\"{ff032593-a8d3-4f13-b0d6-01fc615a0f97}\"/><EventID>5</EventID><Version>3</Version><Level>4</Level><Task>5</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime=\"2021-10-16T00:41:27.577774000Z\"/><EventRecordID>765</EventRecordID><Correlation/><Execution ProcessID=\"3465\" ThreadID=\"3465\"/><Channel>Linux-Sysmon/Operational</Channel><Computer>lsys</Computer><Security UserId=\"0\"/></System><EventData><Data Name=\"RuleName\">-</Data><Data Name=\"UtcTime\">2021-10-16 00:41:27.582</Data><Data Name=\"ProcessGuid\">{3d2a1117-1fb7-616a-69ad-11b4fd550000}</Data><Data Name=\"ProcessId\">3526</Data><Data Name=\"Image\">/usr/bin/sysmon</Data><Data Name=\"User\">root</Data></EventData></Event>"

const MESSAGE_1 = "Oct 15 19:41:20 lsys sysmon: <Event><System><Provider Name=\"Linux-Sysmon\" Guid=\"{ff032593-a8d3-4f13-b0d6-01fc615a0f97}\"/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime=\"2021-10-16T00:41:20.013924000Z\"/><EventRecordID>762</EventRecordID><Correlation/><Execution ProcessID=\"3465\" ThreadID=\"3465\"/><Channel>Linux-Sysmon/Operational</Channel><Computer>lsys</Computer><Security UserId=\"0\"/></System><EventData><Data Name=\"RuleName\">-</Data><Data Name=\"UtcTime\">2021-10-16 00:41:20.017</Data><Data Name=\"ProcessGuid\">{3d2a1117-1fb0-616a-69bd-09c0cb550000}</Data><Data Name=\"ProcessId\">3525</Data><Data Name=\"Image\">/usr/bin/sysmon</Data><Data Name=\"FileVersion\">-</Data><Data Name=\"Description\">-</Data><Data Name=\"Product\">-</Data><Data Name=\"Company\">-</Data><Data Name=\"OriginalFileName\">-</Data><Data Name=\"CommandLine\">sysmon -h</Data><Data Name=\"CurrentDirectory\">/root</Data><Data Name=\"User\">root</Data><Data Name=\"LogonGuid\">{3d2a1117-d3b6-6168-0000-000002000000}</Data><Data Name=\"LogonId\">0</Data><Data Name=\"TerminalSessionId\">1</Data><Data Name=\"IntegrityLevel\">no level</Data><Data Name=\"Hashes\">-</Data><Data Name=\"ParentProcessGuid\">{00000000-0000-0000-0000-000000000000}</Data><Data Name=\"ParentProcessId\">1571</Data><Data Name=\"ParentImage\">-</Data><Data Name=\"ParentCommandLine\">-</Data><Data Name=\"ParentUser\">-</Data></EventData></Event>"

func main() {

	l, err := net.Listen("tcp", "localhost:3333")
	if err != nil {
		panic(err)
	}

	defer l.Close()

	writer := make(chan []byte, 1000)
	closeChannel := make(chan interface{})

	termChan := make(chan os.Signal)
	signal.Notify(termChan, syscall.SIGTERM, syscall.SIGINT)

	wg := &sync.WaitGroup{}

	go fileWriter(writer)

	go func() {
		<-termChan
		fmt.Println("Shutting Down...")
		close(closeChannel)
		defer l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if e, ok := err.(*net.OpError); ok {
				if e.Err.Error() == "use of closed network connection" {
					break
				}
			}
			fmt.Println(err.Error())
			panic(err)
		}
		wg.Add(1)
		go handleRequest(conn, writer, wg, closeChannel)
	}

	fmt.Println("here")
	wg.Wait()
	close(writer)
}

func handleRequest(conn net.Conn, writer chan []byte, wg *sync.WaitGroup, closeChannel chan interface{}) {
	defer conn.Close()
	defer wg.Done()
	for {
		select {
		case <-closeChannel:
			fmt.Println("Closing Connection")
			return
		default:
			conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
			netData, err := bufio.NewReader(conn).ReadString('\n')
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					continue
				} else if err == io.EOF {
					return
				}
				panic(err)
			}
			netDateString := string(netData)
			if !strings.Contains(netDateString, ": ") {
				return
			}
			var a string = strings.Split(string(netData), ": ")[1]
			var b sysmon.Event
			if err := xml.Unmarshal([]byte(a), &b); err != nil {
				panic(err)
			}

			uu := b.ConvertToJson()
			u, _ := json.Marshal(uu)
			writer <- u
		}
	}

}

func fileWriter(writer chan []byte) {
	f, _ := os.OpenFile("test.json", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	for {
		msg := <-writer
		f.Write([]byte(string(msg) + "\n"))
	}
}
