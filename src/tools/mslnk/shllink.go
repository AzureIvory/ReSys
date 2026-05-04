package mslnk

import (
	"bytes"
	"os"
)

type ShellLink struct {
	ShellLinkHeader  header
	LinkTargetIDList LinkTargetIDList
	LinkInfo         LinkInfo
	StringData       StringData
	ExtraData        []byte
}

func (x *ShellLink) Bytes() []byte {
	var buffer bytes.Buffer
	buffer.Write(x.ShellLinkHeader.Bytes())
	if x.ShellLinkHeader.LinkFlags["HasLinkTargetIDList"] {
		buffer.Write(x.LinkTargetIDList.Bytes())
	}
	if x.ShellLinkHeader.LinkFlags["HasLinkInfo"] {
		buffer.Write(x.LinkInfo.Bytes())
	}
	buffer.Write(x.StringData.Bytes())
	buffer.Write(x.ExtraData)
	return buffer.Bytes()
}

func (x *ShellLink) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	data := x.Bytes()
	if _, err := f.Write(data); err != nil {
		return err
	}

	if err := f.Sync(); err != nil {
		return err
	}

	return nil
}
