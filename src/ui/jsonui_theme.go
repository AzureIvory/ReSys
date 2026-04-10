//go:build windows

// UI 主题（Theme）定义。
//
// JSONUI 负责“声明控件与布局”，但控件的字体、颜色、圆角、间距、对齐等细节
// 由 Theme 统一配置。这里的 Theme 会被注入到 jsonui.LoadOptions.Theme 中，
// 作用范围覆盖整个窗口。
package ui

import (
	"github.com/AzureIvory/winui/core"
	"github.com/AzureIvory/winui/widgets"
)

// resysTheme 返回 ReSys 的统一主题配置。
//
// 说明：
// - 所有 SizeDP/CornerRadius 等均以 DP 为单位，winui 会根据 DPI 自动缩放。
// - Text.Format 使用 DrawText 标志位，确保文本在常用控件（按钮/标题/标签）中水平+垂直居中。
// - Button.Border 设置为 0，用于实现“无边框按钮”（主页大按钮、顶部按钮等）。
func resysTheme() *widgets.Theme {
	theme := widgets.DefaultTheme()
	theme.Text = widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 16,
		},
		Color:  core.RGB(15, 23, 42),
		Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
	}
	theme.Title = widgets.TextStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 20,
			Weight: 700,
		},
		Color:  core.RGB(15, 23, 42),
		Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
	}
	theme.Button = selectButtonStyle()
	theme.Button.Border = 0
	theme.Progress = widgets.ProgressStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 14,
			Weight: 700,
		},
		TextColor:    core.RGB(255, 255, 255),
		TrackColor:   core.RGB(243, 244, 246),
		FillColor:    core.RGB(34, 197, 94),
		BubbleColor:  core.RGB(22, 163, 74),
		CornerRadius: 12,
		ShowPercent:  true,
	}

	theme.ListBox.Font = widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12}
	theme.ListBox.ItemHeightDP = 28
	theme.ListBox.PaddingDP = 6
	theme.ListBox.CornerRadius = 10
	theme.ListBox.BorderColor = core.RGB(203, 213, 225)
	theme.ListBox.HoverBorder = core.RGB(59, 130, 246)
	theme.ListBox.FocusBorder = core.RGB(37, 99, 235)
	theme.ListBox.ItemSelectedColor = core.RGB(37, 99, 235)
	theme.ListBox.ItemTextColor = core.RGB(255, 255, 255)

	theme.ComboBox.Font = widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12}
	theme.ComboBox.PaddingDP = 8
	theme.ComboBox.CornerRadius = 10
	theme.ComboBox.MaxVisibleItems = 8
	theme.ComboBox.BorderColor = core.RGB(203, 213, 225)
	theme.ComboBox.HoverBorder = core.RGB(59, 130, 246)
	theme.ComboBox.FocusBorder = core.RGB(37, 99, 235)
	theme.ComboBox.ItemSelectedColor = core.RGB(37, 99, 235)
	theme.ComboBox.ItemTextColor = core.RGB(255, 255, 255)

	theme.Edit.Font = widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12}
	theme.Edit.PaddingDP = 8
	theme.Edit.CornerRadius = 10
	theme.Edit.Background = core.RGB(255, 255, 255)
	theme.Edit.BorderColor = core.RGB(203, 213, 225)
	theme.Edit.HoverBorder = core.RGB(59, 130, 246)
	theme.Edit.FocusBorder = core.RGB(37, 99, 235)
	theme.Edit.DisabledBg = theme.Edit.Background
	theme.Edit.DisabledText = core.RGB(30, 41, 59)

	theme.CheckBox.Font = widgets.FontSpec{Face: "Microsoft YaHei UI", SizeDP: 12}
	theme.CheckBox.IndicatorSizeDP = 16
	theme.CheckBox.IndicatorGapDP = 8
	theme.RadioButton = theme.CheckBox

	return theme
}

// selectButtonStyle 是“选择页”三张系统卡片按钮的默认样式。
// 这些按钮通常包含图标与文字，因此 IconSizeDP/TextInsetDP/GapDP 需要一起配合。
func selectButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 15,
			Weight: 700,
		},
		TextAlign:    widgets.AlignCenter,
		TextColor:    core.RGB(15, 23, 42),
		DownText:     core.RGB(255, 255, 255),
		DisabledText: core.RGB(148, 163, 184),
		Background:   core.RGB(255, 255, 255),
		Hover:        core.RGB(248, 250, 252),
		Pressed:      core.RGB(37, 99, 235),
		Disabled:     core.RGB(241, 245, 249),
		Border:       core.RGB(226, 232, 240),
		CornerRadius: 12,
		IconSizeDP:   40,
		TextInsetDP:  24,
		GapDP:        8,
		PadDP:        12,
	}
}

// dialogPrimaryButtonStyle 用于对话框的“主按钮”样式（例如 BitLocker prompt 的确认按钮）。
// 该类按钮通常强调主操作，因此使用纯色背景并关闭边框。
func dialogPrimaryButtonStyle() widgets.ButtonStyle {
	return widgets.ButtonStyle{
		Font: widgets.FontSpec{
			Face:   "Microsoft YaHei UI",
			SizeDP: 14,
			Weight: 700,
		},
		TextAlign:    widgets.AlignCenter,
		TextColor:    core.RGB(255, 255, 255),
		DownText:     core.RGB(255, 255, 255),
		DisabledText: core.RGB(191, 219, 254),
		Background:   core.RGB(37, 99, 235),
		Hover:        core.RGB(29, 78, 216),
		Pressed:      core.RGB(30, 64, 175),
		Disabled:     core.RGB(96, 165, 250),
		Border:       0,
		CornerRadius: 10,
		PadDP:        12,
	}
}
