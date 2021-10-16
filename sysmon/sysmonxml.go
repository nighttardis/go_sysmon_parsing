package sysmon

import (
	"time"
)

type Event struct {
	// XMLName xml.Name     `xml:"Event"`
	System    SystemStruct    `xml:"System"`
	EventData EventDataStruct `xml:"EventData"`
}

type SystemStruct struct {
	// XMLName       xml.Name          `xml:"System"`
	Provider      ProviderStuct     `xml:"Provider"`
	EventID       int               `xml:"EventID"`
	Version       int               `xml:"Version"`
	Level         int               `xml:"Level"`
	Task          int               `xml:"Task"`
	Opcode        int               `xml:"Opcode"`
	Keywords      string            `xml:"Keywords"`
	TimeCreated   TimeCreatedSturct `xml:"TimeCreated"`
	EventRecordID int               `xml:"EventRecordID"`
	Execution     ExecutionStruct   `xml:"Execution"`
	Channel       string            `xml:"Channel"`
	Computer      string            `xml:"Computer"`
	Security      SecurityStruct    `xml:"Security"`
}

type ProviderStuct struct {
	// XMLName xml.Name `xml:"Provider"`
	Name string `xml:"Name,attr"`
	Guid string `xml:"Guid,attr"`
}

type TimeCreatedSturct struct {
	TimeCreated time.Time `xml:"SystemTime,attr"`
}

type ExecutionStruct struct {
	// XMLName   xml.Name `xml:"Execution"`
	ProcessID int `xml:"ProcessID,attr"`
	ThreadID  int `xml:"ThreadID,attr"`
}

type SecurityStruct struct {
	// XMLName xml.Name `xml:"Security"`
	UserId int `xml:"UserId,attr"`
}

type EventDataStruct struct {
	Data []DataStruct `xml:"Data"`
}

type DataStruct struct {
	Name    string `xml:"Name,attr"`
	Content string `xml:",chardata"`
}
