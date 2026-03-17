package core

import (
	"bytes"
	"image"
	"image/draw"
	"image/gif"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procBeginPaint            = user32.NewProc("BeginPaint")
	procEndPaint              = user32.NewProc("EndPaint")
	procFillRect              = user32.NewProc("FillRect")
	procDrawTextW             = user32.NewProc("DrawTextW")
	procDrawIconEx            = user32.NewProc("DrawIconEx")
	procCreateIconFromResEx   = user32.NewProc("CreateIconFromResourceEx")
	procDestroyIcon           = user32.NewProc("DestroyIcon")
	procCreateSolidBrush      = gdi32.NewProc("CreateSolidBrush")
	procCreatePen             = gdi32.NewProc("CreatePen")
	procCreateFontIndirectW   = gdi32.NewProc("CreateFontIndirectW")
	procCreateCompatibleDC    = gdi32.NewProc("CreateCompatibleDC")
	procDeleteDC              = gdi32.NewProc("DeleteDC")
	procDeleteObject          = gdi32.NewProc("DeleteObject")
	procSelectObject          = gdi32.NewProc("SelectObject")
	procRoundRect             = gdi32.NewProc("RoundRect")
	procPolygon               = gdi32.NewProc("Polygon")
	procGetTextExtentPoint32W = gdi32.NewProc("GetTextExtentPoint32W")
	procSetBkMode             = gdi32.NewProc("SetBkMode")
	procSetTextColor          = gdi32.NewProc("SetTextColor")
	procCreateDIBSection      = gdi32.NewProc("CreateDIBSection")
	procBitBlt                = gdi32.NewProc("BitBlt")
	procGetStockObject        = gdi32.NewProc("GetStockObject")
	procAlphaBlend            = msimg32.NewProc("AlphaBlend")
)

const (
	nullBrush = 5
	nullPen   = 8
)

type paintStruct struct {
	Hdc         windows.Handle
	FErase      int32
	RcPaint     winRect
	FRestore    int32
	FIncUpdate  int32
	RgbReserved [32]byte
}

type logFontW struct {
	Height         int32
	Width          int32
	Escapement     int32
	Orientation    int32
	Weight         int32
	Italic         byte
	Underline      byte
	StrikeOut      byte
	CharSet        byte
	OutPrecision   byte
	ClipPrecision  byte
	Quality        byte
	PitchAndFamily byte
	FaceName       [32]uint16
}

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type bitmapInfo struct {
	Header bitmapInfoHeader
	Colors [1]uint32
}

type blendFunction struct {
	BlendOp             byte
	BlendFlags          byte
	SourceConstantAlpha byte
	AlphaFormat         byte
}

type Font struct {
	handle windows.Handle
}

type Brush struct {
	handle windows.Handle
}

type Pen struct {
	handle windows.Handle
}

type Icon struct {
	handle windows.Handle
}

type Bitmap struct {
	handle windows.Handle
	Width  int32
	Height int32
}

type AnimatedFrame struct {
	Bitmap *Bitmap
	Width  int32
	Height int32
	Delay  time.Duration
}

type Canvas struct {
	hdc    windows.Handle
	bounds Rect
}

type PaintCtx = Canvas

type paintSession struct {
	hwnd      windows.Handle
	paintDC   windows.Handle
	memDC     windows.Handle
	oldBitmap uintptr
	buffer    *Bitmap
	canvas    *Canvas
	ps        paintStruct
	direct    bool
}

func NewSolidBrush(color Color) (*Brush, error) {
	h, _, err := procCreateSolidBrush.Call(uintptr(color))
	if h == 0 {
		return nil, wrapError("CreateSolidBrush", err)
	}
	return &Brush{handle: windows.Handle(h)}, nil
}

func (b *Brush) Handle() windows.Handle {
	if b == nil {
		return 0
	}
	return b.handle
}

func (b *Brush) Close() error {
	if b == nil || b.handle == 0 {
		return nil
	}
	h := b.handle
	b.handle = 0
	r1, _, err := procDeleteObject.Call(uintptr(h))
	if r1 == 0 {
		return wrapError("DeleteObject(brush)", err)
	}
	return nil
}

func NewPen(width int32, color Color) (*Pen, error) {
	h, _, err := procCreatePen.Call(psSolid, uintptr(width), uintptr(color))
	if h == 0 {
		return nil, wrapError("CreatePen", err)
	}
	return &Pen{handle: windows.Handle(h)}, nil
}

func (p *Pen) Handle() windows.Handle {
	if p == nil {
		return 0
	}
	return p.handle
}

func (p *Pen) Close() error {
	if p == nil || p.handle == 0 {
		return nil
	}
	h := p.handle
	p.handle = 0
	r1, _, err := procDeleteObject.Call(uintptr(h))
	if r1 == 0 {
		return wrapError("DeleteObject(pen)", err)
	}
	return nil
}

func NewFont(face string, height int32, weight int32, quality FontQuality) (*Font, error) {
	var lf logFontW
	lf.Height = -height
	lf.Weight = weight
	lf.CharSet = 1
	lf.Quality = byte(quality)
	copy(lf.FaceName[:], windows.StringToUTF16(face))

	h, _, err := procCreateFontIndirectW.Call(uintptr(unsafe.Pointer(&lf)))
	if h == 0 {
		return nil, wrapError("CreateFontIndirectW", err)
	}
	return &Font{handle: windows.Handle(h)}, nil
}

func (a *App) NewFont(face string, heightDP int32, weight int32) (*Font, error) {
	return NewFont(face, a.DP(heightDP), weight, FontQualityClearType)
}

func (f *Font) Handle() windows.Handle {
	if f == nil {
		return 0
	}
	return f.handle
}

func (f *Font) Close() error {
	if f == nil || f.handle == 0 {
		return nil
	}
	h := f.handle
	f.handle = 0
	r1, _, err := procDeleteObject.Call(uintptr(h))
	if r1 == 0 {
		return wrapError("DeleteObject(font)", err)
	}
	return nil
}

func LoadIconFromICO(data []byte, want int32) (*Icon, error) {
	if len(data) < 6 {
		return nil, wrapError("CreateIconFromResourceEx", windows.ERROR_INVALID_DATA)
	}

	count := int(*(*uint16)(unsafe.Pointer(&data[4])))
	if count <= 0 {
		return nil, wrapError("CreateIconFromResourceEx", windows.ERROR_INVALID_DATA)
	}

	type iconDirEntry struct {
		W, H        byte
		ColorCount  byte
		Reserved    byte
		Planes      uint16
		BitCount    uint16
		BytesInRes  uint32
		ImageOffset uint32
	}

	best := -1
	bestScore := int32(1 << 30)
	for i := 0; i < count; i++ {
		offset := 6 + i*16
		if offset+16 > len(data) {
			break
		}
		entry := (*iconDirEntry)(unsafe.Pointer(&data[offset]))
		w := int32(entry.W)
		h := int32(entry.H)
		if w == 0 {
			w = 256
		}
		if h == 0 {
			h = 256
		}
		score := abs32(w-want) + abs32(h-want)
		if score < bestScore {
			bestScore = score
			best = i
		}
	}
	if best < 0 {
		return nil, wrapError("CreateIconFromResourceEx", windows.ERROR_INVALID_DATA)
	}

	entry := (*iconDirEntry)(unsafe.Pointer(&data[6+best*16]))
	start := int(entry.ImageOffset)
	end := start + int(entry.BytesInRes)
	if start < 0 || end > len(data) || start >= end {
		return nil, wrapError("CreateIconFromResourceEx", windows.ERROR_INVALID_DATA)
	}

	raw := data[start:end]
	h, _, err := procCreateIconFromResEx.Call(
		uintptr(unsafe.Pointer(&raw[0])),
		uintptr(len(raw)),
		1,
		0x00030000,
		uintptr(want),
		uintptr(want),
		0,
	)
	if h == 0 {
		return nil, wrapError("CreateIconFromResourceEx", err)
	}
	return &Icon{handle: windows.Handle(h)}, nil
}

func (i *Icon) Handle() windows.Handle {
	if i == nil {
		return 0
	}
	return i.handle
}

func (i *Icon) Close() error {
	if i == nil || i.handle == 0 {
		return nil
	}
	h := i.handle
	i.handle = 0
	r1, _, err := procDestroyIcon.Call(uintptr(h))
	if r1 == 0 {
		return wrapError("DestroyIcon", err)
	}
	return nil
}

func BitmapFromRGBA(img *image.RGBA) (*Bitmap, error) {
	w := int32(img.Bounds().Dx())
	h := int32(img.Bounds().Dy())
	if w <= 0 || h <= 0 {
		return nil, wrapError("CreateDIBSection", windows.ERROR_INVALID_DATA)
	}

	var bi bitmapInfo
	bi.Header.Size = uint32(unsafe.Sizeof(bi.Header))
	bi.Header.Width = w
	bi.Header.Height = -h
	bi.Header.Planes = 1
	bi.Header.BitCount = 32

	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return nil, wrapError("GetDC", windows.ERROR_INVALID_WINDOW_HANDLE)
	}
	defer procReleaseDC.Call(0, hdc)

	var bits unsafe.Pointer
	hbmp, _, err := procCreateDIBSection.Call(
		hdc,
		uintptr(unsafe.Pointer(&bi)),
		0,
		uintptr(unsafe.Pointer(&bits)),
		0,
		0,
	)
	if hbmp == 0 {
		return nil, wrapError("CreateDIBSection", err)
	}

	dst := unsafe.Slice((*byte)(bits), int(w*h*4))
	for i := 0; i < len(img.Pix); i += 4 {
		r := img.Pix[i]
		g := img.Pix[i+1]
		b := img.Pix[i+2]
		a := img.Pix[i+3]

		pr := byte(uint16(r) * uint16(a) / 255)
		pg := byte(uint16(g) * uint16(a) / 255)
		pb := byte(uint16(b) * uint16(a) / 255)

		dst[i] = pb
		dst[i+1] = pg
		dst[i+2] = pr
		dst[i+3] = a
	}

	return &Bitmap{
		handle: windows.Handle(hbmp),
		Width:  w,
		Height: h,
	}, nil
}

func (b *Bitmap) Handle() windows.Handle {
	if b == nil {
		return 0
	}
	return b.handle
}

func (b *Bitmap) Close() error {
	if b == nil || b.handle == 0 {
		return nil
	}
	h := b.handle
	b.handle = 0
	r1, _, err := procDeleteObject.Call(uintptr(h))
	if r1 == 0 {
		return wrapError("DeleteObject(bitmap)", err)
	}
	return nil
}

func DecodeGIF(data []byte) ([]AnimatedFrame, error) {
	all, err := gif.DecodeAll(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	canvas := image.NewRGBA(image.Rect(0, 0, all.Config.Width, all.Config.Height))
	frames := make([]AnimatedFrame, 0, len(all.Image))
	for idx, frame := range all.Image {
		draw.Draw(canvas, frame.Bounds(), frame, frame.Bounds().Min, draw.Over)

		rgba := image.NewRGBA(canvas.Bounds())
		copy(rgba.Pix, canvas.Pix)

		bmp, bmpErr := BitmapFromRGBA(rgba)
		if bmpErr != nil {
			for i := range frames {
				_ = frames[i].Bitmap.Close()
			}
			return nil, bmpErr
		}

		delay := 100 * time.Millisecond
		if idx < len(all.Delay) && all.Delay[idx] > 0 {
			delay = time.Duration(all.Delay[idx]) * 10 * time.Millisecond
		}
		if delay < 10*time.Millisecond {
			delay = 10 * time.Millisecond
		}

		frames = append(frames, AnimatedFrame{
			Bitmap: bmp,
			Width:  bmp.Width,
			Height: bmp.Height,
			Delay:  delay,
		})
	}
	return frames, nil
}

func (c *Canvas) Handle() windows.Handle {
	if c == nil {
		return 0
	}
	return c.hdc
}

func (c *Canvas) Bounds() Rect {
	if c == nil {
		return Rect{}
	}
	return c.bounds
}

func (c *Canvas) FillRect(rect Rect, color Color) error {
	brush, err := NewSolidBrush(color)
	if err != nil {
		return err
	}
	defer brush.Close()

	wr := rect.toWinRect()
	r1, _, fillErr := procFillRect.Call(
		uintptr(c.hdc),
		uintptr(unsafe.Pointer(&wr)),
		uintptr(brush.handle),
	)
	if r1 == 0 {
		return wrapError("FillRect", fillErr)
	}
	return nil
}

func (c *Canvas) Clear(color Color) error {
	return c.FillRect(c.bounds, color)
}

func (c *Canvas) FillRoundRect(rect Rect, radius int32, color Color) error {
	return c.RoundRect(rect, radius, color, color)
}

func (c *Canvas) StrokeRoundRect(rect Rect, radius int32, color Color, width int32) error {
	if width <= 0 {
		width = 1
	}

	pen, err := NewPen(width, color)
	if err != nil {
		return err
	}
	defer pen.Close()

	hollowBrush, _, brushErr := procGetStockObject.Call(nullBrush)
	if hollowBrush == 0 {
		return wrapError("GetStockObject", brushErr)
	}

	oldBrush, _, _ := procSelectObject.Call(uintptr(c.hdc), hollowBrush)
	oldPen, _, _ := procSelectObject.Call(uintptr(c.hdc), uintptr(pen.handle))
	defer procSelectObject.Call(uintptr(c.hdc), oldBrush)
	defer procSelectObject.Call(uintptr(c.hdc), oldPen)

	r1, _, roundErr := procRoundRect.Call(
		uintptr(c.hdc),
		uintptr(rect.X),
		uintptr(rect.Y),
		uintptr(rect.X+rect.W),
		uintptr(rect.Y+rect.H),
		uintptr(radius),
		uintptr(radius),
	)
	if r1 == 0 {
		return wrapError("RoundRect", roundErr)
	}
	return nil
}

func (c *Canvas) FillPolygon(points []Point, color Color) error {
	if len(points) < 3 {
		return nil
	}

	brush, err := NewSolidBrush(color)
	if err != nil {
		return err
	}
	defer brush.Close()

	hollowPen, _, penErr := procGetStockObject.Call(nullPen)
	if hollowPen == 0 {
		return wrapError("GetStockObject", penErr)
	}

	oldBrush, _, _ := procSelectObject.Call(uintptr(c.hdc), uintptr(brush.handle))
	oldPen, _, _ := procSelectObject.Call(uintptr(c.hdc), hollowPen)
	defer procSelectObject.Call(uintptr(c.hdc), oldBrush)
	defer procSelectObject.Call(uintptr(c.hdc), oldPen)

	r1, _, drawErr := procPolygon.Call(
		uintptr(c.hdc),
		uintptr(unsafe.Pointer(&points[0])),
		uintptr(len(points)),
	)
	if r1 == 0 {
		return wrapError("Polygon", drawErr)
	}
	return nil
}

func (c *Canvas) RoundRect(rect Rect, radius int32, fill Color, stroke Color) error {
	brush, err := NewSolidBrush(fill)
	if err != nil {
		return err
	}
	defer brush.Close()

	pen, err := NewPen(1, stroke)
	if err != nil {
		return err
	}
	defer pen.Close()

	oldBrush, _, _ := procSelectObject.Call(uintptr(c.hdc), uintptr(brush.handle))
	oldPen, _, _ := procSelectObject.Call(uintptr(c.hdc), uintptr(pen.handle))
	defer procSelectObject.Call(uintptr(c.hdc), oldBrush)
	defer procSelectObject.Call(uintptr(c.hdc), oldPen)

	r1, _, roundErr := procRoundRect.Call(
		uintptr(c.hdc),
		uintptr(rect.X),
		uintptr(rect.Y),
		uintptr(rect.X+rect.W),
		uintptr(rect.Y+rect.H),
		uintptr(radius),
		uintptr(radius),
	)
	if r1 == 0 {
		return wrapError("RoundRect", roundErr)
	}
	return nil
}

func (c *Canvas) DrawText(text string, rect Rect, font *Font, color Color, format uint32) error {
	if text == "" {
		return nil
	}
	ptr, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return err
	}

	procSetBkMode.Call(uintptr(c.hdc), bkModeTransparent)
	procSetTextColor.Call(uintptr(c.hdc), uintptr(color))

	var oldFont uintptr
	if font != nil && font.handle != 0 {
		oldFont, _, _ = procSelectObject.Call(uintptr(c.hdc), uintptr(font.handle))
		defer procSelectObject.Call(uintptr(c.hdc), oldFont)
	}

	wr := rect.toWinRect()
	r1, _, drawErr := procDrawTextW.Call(
		uintptr(c.hdc),
		uintptr(unsafe.Pointer(ptr)),
		drawTextAutoLen,
		uintptr(unsafe.Pointer(&wr)),
		uintptr(format),
	)
	if r1 == 0 {
		return wrapError("DrawTextW", drawErr)
	}
	return nil
}

// MeasureText 测量文本在当前画布上的像素尺寸。
func (c *Canvas) MeasureText(text string, font *Font) (Size, error) {
	if text == "" {
		return Size{}, nil
	}

	ptr, err := windows.UTF16PtrFromString(text)
	if err != nil {
		return Size{}, err
	}

	var oldFont uintptr
	if font != nil && font.handle != 0 {
		oldFont, _, _ = procSelectObject.Call(uintptr(c.hdc), uintptr(font.handle))
		defer procSelectObject.Call(uintptr(c.hdc), oldFont)
	}

	var size Size
	r1, _, measureErr := procGetTextExtentPoint32W.Call(
		uintptr(c.hdc),
		uintptr(unsafe.Pointer(ptr)),
		uintptr(len([]rune(text))),
		uintptr(unsafe.Pointer(&size)),
	)
	if r1 == 0 {
		return Size{}, wrapError("GetTextExtentPoint32W", measureErr)
	}
	return size, nil
}

func (c *Canvas) DrawIcon(icon *Icon, rect Rect) error {
	if icon == nil || icon.handle == 0 {
		return nil
	}
	r1, _, err := procDrawIconEx.Call(
		uintptr(c.hdc),
		uintptr(rect.X),
		uintptr(rect.Y),
		uintptr(icon.handle),
		uintptr(rect.W),
		uintptr(rect.H),
		0,
		0,
		diNormal,
	)
	if r1 == 0 {
		return wrapError("DrawIconEx", err)
	}
	return nil
}

func (c *Canvas) DrawBitmapAlpha(bitmap *Bitmap, rect Rect, alpha byte) error {
	if bitmap == nil || bitmap.handle == 0 {
		return nil
	}

	srcDC, _, err := procCreateCompatibleDC.Call(uintptr(c.hdc))
	if srcDC == 0 {
		return wrapError("CreateCompatibleDC", err)
	}
	defer procDeleteDC.Call(srcDC)

	old, _, _ := procSelectObject.Call(srcDC, uintptr(bitmap.handle))
	defer procSelectObject.Call(srcDC, old)

	blend := blendFunction{
		BlendOp:             acSrcOver,
		SourceConstantAlpha: alpha,
		AlphaFormat:         acSrcAlpha,
	}
	blendValue := *(*uint32)(unsafe.Pointer(&blend))

	r1, _, alphaErr := procAlphaBlend.Call(
		uintptr(c.hdc),
		uintptr(rect.X),
		uintptr(rect.Y),
		uintptr(rect.W),
		uintptr(rect.H),
		srcDC,
		0,
		0,
		uintptr(bitmap.Width),
		uintptr(bitmap.Height),
		uintptr(blendValue),
	)
	if r1 == 0 {
		return wrapError("AlphaBlend", alphaErr)
	}
	return nil
}

func beginPaintSession(hwnd windows.Handle, doubleBuffered bool) (*paintSession, error) {
	session := &paintSession{hwnd: hwnd}
	paintDC, _, err := procBeginPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&session.ps)))
	if paintDC == 0 {
		return nil, wrapError("BeginPaint", err)
	}
	session.paintDC = windows.Handle(paintDC)

	bounds, err := clientRect(hwnd)
	if err != nil {
		procEndPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&session.ps)))
		return nil, err
	}

	if !doubleBuffered || bounds.Empty() {
		session.direct = true
		session.canvas = &Canvas{hdc: session.paintDC, bounds: bounds}
		return session, nil
	}

	memDC, _, dcErr := procCreateCompatibleDC.Call(uintptr(session.paintDC))
	if memDC == 0 {
		procEndPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&session.ps)))
		return nil, wrapError("CreateCompatibleDC", dcErr)
	}
	session.memDC = windows.Handle(memDC)

	buffer, err := newDIB(bounds.W, bounds.H, session.paintDC)
	if err != nil {
		procDeleteDC.Call(uintptr(session.memDC))
		procEndPaint.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&session.ps)))
		return nil, err
	}

	session.buffer = buffer
	session.oldBitmap, _, _ = procSelectObject.Call(uintptr(session.memDC), uintptr(buffer.handle))
	session.canvas = &Canvas{hdc: session.memDC, bounds: bounds}
	return session, nil
}

func (s *paintSession) close() error {
	if s == nil {
		return nil
	}

	var retErr error
	if !s.direct && s.canvas != nil && s.buffer != nil {
		r1, _, err := procBitBlt.Call(
			uintptr(s.paintDC),
			0,
			0,
			uintptr(s.canvas.bounds.W),
			uintptr(s.canvas.bounds.H),
			uintptr(s.memDC),
			0,
			0,
			srccopy,
		)
		if r1 == 0 && retErr == nil {
			retErr = wrapError("BitBlt", err)
		}
	}

	if s.memDC != 0 {
		procSelectObject.Call(uintptr(s.memDC), s.oldBitmap)
		procDeleteDC.Call(uintptr(s.memDC))
	}
	if s.buffer != nil {
		_ = s.buffer.Close()
	}
	if s.paintDC != 0 {
		procEndPaint.Call(uintptr(s.hwnd), uintptr(unsafe.Pointer(&s.ps)))
	}
	return retErr
}

func newDIB(width, height int32, refDC windows.Handle) (*Bitmap, error) {
	if width <= 0 || height <= 0 {
		return &Bitmap{Width: width, Height: height}, nil
	}

	var bi bitmapInfo
	bi.Header.Size = uint32(unsafe.Sizeof(bi.Header))
	bi.Header.Width = width
	bi.Header.Height = -height
	bi.Header.Planes = 1
	bi.Header.BitCount = 32

	var bits unsafe.Pointer
	hbmp, _, err := procCreateDIBSection.Call(
		uintptr(refDC),
		uintptr(unsafe.Pointer(&bi)),
		0,
		uintptr(unsafe.Pointer(&bits)),
		0,
		0,
	)
	if hbmp == 0 {
		return nil, wrapError("CreateDIBSection", err)
	}

	return &Bitmap{
		handle: windows.Handle(hbmp),
		Width:  width,
		Height: height,
	}, nil
}

func abs32(v int32) int32 {
	if v < 0 {
		return -v
	}
	return v
}
