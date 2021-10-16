package sysmon

import (
	"strconv"
	"time"
)

var ConvertInt = map[string]bool{
	"ProcessId":         true,
	"LogonId":           true,
	"TerminalSessionId": true,
	"ParentProcessId":   true,
}

type JsonEvent struct {
	System    JsonSystemStruct         `json:"System"`
	EventData []map[string]interface{} `json:"EventData"`
}

type JsonSystemStruct struct {
	Provider      JsonProviderStuct   `Json:"Provider"`
	EventID       int                 `json:"EventID"`
	Version       int                 `json:"Version"`
	Level         int                 `json:"Level"`
	Task          int                 `json:"Task"`
	Opcode        int                 `json:"Opcode"`
	Keywords      string              `json:"Keywords"`
	TimeCreated   time.Time           `json:"TimeCreated"`
	EventRecordID int                 `json:"EventRecordID"`
	Channel       string              `json:"Channel"`
	Computer      string              `json:"Computer"`
	Execution     JsonExecutionStruct `json:"Execution"`
	Security      JsonSecurityStruct  `json:"Security"`
}

type JsonProviderStuct struct {
	Name string `json:"Name"`
	Guid string `json:"Guid"`
}

type JsonExecutionStruct struct {
	ProcessID int `json:"ProcessID"`
	ThreadID  int `json:"ThreadID"`
}

type JsonSecurityStruct struct {
	UserId int `json:"UserId"`
}

func (e *Event) ConvertToJson() *JsonEvent {
	var returnEvent JsonEvent
	returnEvent.System.Provider = JsonProviderStuct(e.System.Provider)
	returnEvent.System.Execution = JsonExecutionStruct(e.System.Execution)
	returnEvent.System.Security = JsonSecurityStruct(e.System.Security)
	returnEvent.System.EventID = e.System.EventID
	returnEvent.System.Version = e.System.Version
	returnEvent.System.Level = e.System.Level
	returnEvent.System.Task = e.System.Task
	returnEvent.System.Opcode = e.System.Opcode
	returnEvent.System.Keywords = e.System.Keywords
	returnEvent.System.TimeCreated = e.System.TimeCreated.TimeCreated
	returnEvent.System.EventRecordID = e.System.EventRecordID
	returnEvent.System.Channel = e.System.Channel
	returnEvent.System.Computer = e.System.Computer
	for _, r := range e.EventData.Data {
		m := make(map[string]interface{})
		if ConvertInt[r.Name] {
			if i, err := strconv.Atoi(r.Content); err == nil {
				m[r.Name] = i
			}
		} else {
			m[r.Name] = r.Content
		}
		returnEvent.EventData = append(returnEvent.EventData, m)
	}
	// u, _ := json.Marshal(returnEvent)
	// fmt.Println(string(u))
	// fmt.Println(returnEvent.System)
	return &returnEvent
}
