package widgets

import "ReSys/src/winui/core"

type FontSpec struct {
	Face   string
	SizeDP int32
	Weight int32
}

type TextStyle struct {
	Font   FontSpec
	Color  core.Color
	Format uint32
}

type ButtonStyle struct {
	Font         FontSpec
	TextColor    core.Color
	DisabledText core.Color
	Background   core.Color
	Hover        core.Color
	Pressed      core.Color
	Disabled     core.Color
	Border       core.Color
	CornerRadius int32
	IconSizeDP   int32
	TextInsetDP  int32
}

type ProgressStyle struct {
	Font         FontSpec
	TextColor    core.Color
	TrackColor   core.Color
	FillColor    core.Color
	BubbleColor  core.Color
	CornerRadius int32
	ShowPercent  bool
}

type ChoiceStyle struct {
	Font            FontSpec
	TextColor       core.Color
	DisabledText    core.Color
	Background      core.Color
	BorderColor     core.Color
	HoverBorder     core.Color
	FocusBorder     core.Color
	IndicatorColor  core.Color
	CheckColor      core.Color
	HoverBackground core.Color
	DisabledBg      core.Color
	DisabledBorder  core.Color
	CornerRadius    int32
	IndicatorSizeDP int32
	IndicatorGapDP  int32
}

type ListStyle struct {
	Font              FontSpec
	TextColor         core.Color
	DisabledText      core.Color
	Background        core.Color
	BorderColor       core.Color
	HoverBorder       core.Color
	FocusBorder       core.Color
	ItemHoverColor    core.Color
	ItemSelectedColor core.Color
	ItemTextColor     core.Color
	ItemHeightDP      int32
	PaddingDP         int32
	CornerRadius      int32
}

type ComboStyle struct {
	Font              FontSpec
	TextColor         core.Color
	PlaceholderColor  core.Color
	Background        core.Color
	BorderColor       core.Color
	HoverBorder       core.Color
	FocusBorder       core.Color
	ArrowColor        core.Color
	PopupBackground   core.Color
	ItemHoverColor    core.Color
	ItemSelectedColor core.Color
	ItemTextColor     core.Color
	ItemHeightDP      int32
	PaddingDP         int32
	CornerRadius      int32
	MaxVisibleItems   int32
}

type EditStyle struct {
	Font             FontSpec
	TextColor        core.Color
	PlaceholderColor core.Color
	Background       core.Color
	BorderColor      core.Color
	HoverBorder      core.Color
	FocusBorder      core.Color
	DisabledText     core.Color
	DisabledBg       core.Color
	CaretColor       core.Color
	PaddingDP        int32
	CornerRadius     int32
}

type Theme struct {
	BackgroundColor core.Color
	Text            TextStyle
	Title           TextStyle
	Button          ButtonStyle
	Progress        ProgressStyle
	CheckBox        ChoiceStyle
	RadioButton     ChoiceStyle
	ListBox         ListStyle
	ComboBox        ComboStyle
	Edit            EditStyle
}

func DefaultTheme() *Theme {
	return &Theme{
		BackgroundColor: core.RGB(255, 255, 255),
		Text: TextStyle{
			Font: FontSpec{
				Face:   "Microsoft YaHei UI",
				SizeDP: 16,
			},
			Color:  core.RGB(16, 16, 16),
			Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
		},
		Title: TextStyle{
			Font: FontSpec{
				Face:   "Microsoft YaHei UI",
				SizeDP: 20,
			},
			Color:  core.RGB(16, 16, 16),
			Format: core.DTCenter | core.DTVCenter | core.DTSingleLine,
		},
		Button: ButtonStyle{
			Font: FontSpec{
				Face:   "Microsoft YaHei UI",
				SizeDP: 16,
			},
			TextColor:    core.RGB(16, 16, 16),
			DisabledText: core.RGB(100, 100, 100),
			Background:   core.RGB(255, 255, 255),
			Hover:        core.RGB(242, 244, 247),
			Pressed:      core.RGB(0, 120, 215),
			Disabled:     core.RGB(35, 35, 35),
			Border:       core.RGB(255, 255, 255),
			CornerRadius: 8,
			IconSizeDP:   48,
			TextInsetDP:  35,
		},
		Progress: ProgressStyle{
			Font: FontSpec{
				Face:   "Microsoft YaHei UI",
				SizeDP: 14,
				Weight: 700,
			},
			TextColor:    core.RGB(255, 255, 255),
			TrackColor:   core.RGB(243, 244, 246),
			FillColor:    core.RGB(124, 58, 237),
			BubbleColor:  core.RGB(109, 40, 217),
			CornerRadius: 12,
			ShowPercent:  true,
		},
		CheckBox: ChoiceStyle{
			Font: FontSpec{
				Face:   "Microsoft YaHei UI",
				SizeDP: 15,
			},
			TextColor:       core.RGB(31, 41, 55),
			DisabledText:    core.RGB(156, 163, 175),
			Background:      core.RGB(255, 255, 255),
			BorderColor:     core.RGB(203, 213, 225),
			HoverBorder:     core.RGB(124, 58, 237),
			FocusBorder:     core.RGB(109, 40, 217),
			IndicatorColor:  core.RGB(124, 58, 237),
			CheckColor:      core.RGB(255, 255, 255),
			HoverBackground: core.RGB(245, 243, 255),
			DisabledBg:      core.RGB(243, 244, 246),
			DisabledBorder:  core.RGB(209, 213, 219),
			CornerRadius:    6,
			IndicatorSizeDP: 18,
			IndicatorGapDP:  10,
		},
		RadioButton: ChoiceStyle{
			Font: FontSpec{
				Face:   "Microsoft YaHei UI",
				SizeDP: 15,
			},
			TextColor:       core.RGB(31, 41, 55),
			DisabledText:    core.RGB(156, 163, 175),
			Background:      core.RGB(255, 255, 255),
			BorderColor:     core.RGB(203, 213, 225),
			HoverBorder:     core.RGB(124, 58, 237),
			FocusBorder:     core.RGB(109, 40, 217),
			IndicatorColor:  core.RGB(124, 58, 237),
			CheckColor:      core.RGB(255, 255, 255),
			HoverBackground: core.RGB(245, 243, 255),
			DisabledBg:      core.RGB(243, 244, 246),
			DisabledBorder:  core.RGB(209, 213, 219),
			CornerRadius:    9,
			IndicatorSizeDP: 18,
			IndicatorGapDP:  10,
		},
		ListBox: ListStyle{
			Font: FontSpec{
				Face:   "Microsoft YaHei UI",
				SizeDP: 15,
			},
			TextColor:         core.RGB(31, 41, 55),
			DisabledText:      core.RGB(156, 163, 175),
			Background:        core.RGB(255, 255, 255),
			BorderColor:       core.RGB(203, 213, 225),
			HoverBorder:       core.RGB(167, 139, 250),
			FocusBorder:       core.RGB(124, 58, 237),
			ItemHoverColor:    core.RGB(245, 243, 255),
			ItemSelectedColor: core.RGB(124, 58, 237),
			ItemTextColor:     core.RGB(255, 255, 255),
			ItemHeightDP:      34,
			PaddingDP:         8,
			CornerRadius:      10,
		},
		ComboBox: ComboStyle{
			Font: FontSpec{
				Face:   "Microsoft YaHei UI",
				SizeDP: 15,
			},
			TextColor:         core.RGB(31, 41, 55),
			PlaceholderColor:  core.RGB(156, 163, 175),
			Background:        core.RGB(255, 255, 255),
			BorderColor:       core.RGB(203, 213, 225),
			HoverBorder:       core.RGB(167, 139, 250),
			FocusBorder:       core.RGB(124, 58, 237),
			ArrowColor:        core.RGB(109, 40, 217),
			PopupBackground:   core.RGB(255, 255, 255),
			ItemHoverColor:    core.RGB(245, 243, 255),
			ItemSelectedColor: core.RGB(124, 58, 237),
			ItemTextColor:     core.RGB(255, 255, 255),
			ItemHeightDP:      34,
			PaddingDP:         10,
			CornerRadius:      10,
			MaxVisibleItems:   6,
		},
		Edit: EditStyle{
			Font: FontSpec{
				Face:   "Microsoft YaHei UI",
				SizeDP: 15,
			},
			TextColor:        core.RGB(31, 41, 55),
			PlaceholderColor: core.RGB(156, 163, 175),
			Background:       core.RGB(255, 255, 255),
			BorderColor:      core.RGB(203, 213, 225),
			HoverBorder:      core.RGB(167, 139, 250),
			FocusBorder:      core.RGB(124, 58, 237),
			DisabledText:     core.RGB(156, 163, 175),
			DisabledBg:       core.RGB(243, 244, 246),
			CaretColor:       core.RGB(109, 40, 217),
			PaddingDP:        10,
			CornerRadius:     10,
		},
	}
}
