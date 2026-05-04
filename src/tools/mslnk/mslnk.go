package mslnk

import (
	"errors"
	"strings"
)

// Options 是离线生成 .lnk 的高层配置。
// TargetPath 和 LinkPath 是 CreateLink 的必填项；NewLink 只要求 TargetPath。
type Options struct {
	TargetPath   string
	LinkPath     string
	WorkingDir   string
	Arguments    string
	IconLocation string
	Description  string
	RelativePath string
	ShowCommand  string
}

// LinkFile 保留旧 API。它现在走新的离线生成路径，但仍只接收目标和输出路径。
func LinkFile(target string, name string) error {
	return CreateLink(Options{TargetPath: target, LinkPath: name})
}

// CreateLink 根据 Options 创建并保存 .lnk 文件。
func CreateLink(opts Options) error {
	if strings.TrimSpace(opts.LinkPath) == "" {
		return errors.New("mslnk: LinkPath is required")
	}
	link, err := NewLink(opts)
	if err != nil {
		return err
	}
	return link.Save(opts.LinkPath)
}

// NewLink 构造一个纯离线的 ShellLink，不访问目标文件系统。
func NewLink(opts Options) (*ShellLink, error) {
	target, err := normalizeTargetPath(opts.TargetPath)
	if err != nil {
		return nil, err
	}

	header := Header()
	header.LinkFlags["HasLinkInfo"] = true
	header.LinkFlags["ForceNoLinkInfo"] = false
	header.LinkFlags["IsUnicode"] = true
	header.FileAttributes["FILE_ATTRIBUTE_NORMAL"] = true

	var targetIDList LinkTargetIDList
	if idList, ok := newLocalTargetIDList(target); ok {
		targetIDList = idList
		header.LinkFlags["HasLinkTargetIDList"] = true
	}

	if opts.ShowCommand != "" {
		showCommand, ok := ShowCommand[opts.ShowCommand]
		if !ok {
			return nil, errors.New("mslnk: unsupported ShowCommand")
		}
		header.Data.ShowCommand = showCommand
	}

	stringData := StringData{}
	if opts.Description != "" {
		stringData["NameString"] = StringDataStruct(opts.Description)
	}
	if opts.RelativePath != "" {
		stringData["RelativePath"] = StringDataStruct(opts.RelativePath)
	}
	if opts.WorkingDir != "" {
		stringData["WorkingDir"] = StringDataStruct(normalizeWindowsSlashes(opts.WorkingDir))
	}
	if opts.Arguments != "" {
		stringData["CommandLineArguments"] = StringDataStruct(opts.Arguments)
	}
	if opts.IconLocation != "" {
		stringData["IconLocation"] = StringDataStruct(normalizeWindowsSlashes(opts.IconLocation))
	}
	stringData.Update(&header)
	header.Update()

	return &ShellLink{
		ShellLinkHeader:  header,
		LinkTargetIDList: targetIDList,
		LinkInfo:         newLocalLinkInfo(target),
		StringData:       stringData,
		ExtraData:        []byte{0x00, 0x00, 0x00, 0x00},
	}, nil
}

func normalizeTargetPath(target string) (string, error) {
	target = normalizeWindowsSlashes(target)
	if target == "" {
		return "", errors.New("mslnk: TargetPath is required")
	}

	if len(target) >= 3 && target[1] == ':' && target[2] == '\\' {
		return target, nil
	}
	if len(target) >= 2 && target[1] == ':' {
		return target[:2] + "\\" + strings.TrimLeft(target[2:], "\\"), nil
	}

	// 兼容旧 LinkFile：非绝对路径默认按 C:\ 下的目标处理。
	return "C:\\" + strings.TrimLeft(target, "\\"), nil
}

func normalizeWindowsSlashes(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "/", "\\")
}
