package widgets

import (
	"ReSys/src/winui/core"
	"bytes"
	"image"
	"image/draw"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"time"
)

type ImageScaleMode int

const (
	ImageScaleStretch ImageScaleMode = iota + 1
	ImageScaleContain
	ImageScaleCenter
)

type Image struct {
	widgetBase
	bitmap     *core.Bitmap
	owned      bool
	opacity    byte
	scaleMode  ImageScaleMode
	sourceSize core.Size
}

func NewImage(id string) *Image {
	return &Image{
		widgetBase: newWidgetBase(id, "image"),
		opacity:    255,
		scaleMode:  ImageScaleContain,
	}
}

func (i *Image) SetBounds(rect Rect) {
	i.runOnUI(func() {
		i.widgetBase.setBounds(i, rect)
	})
}

func (i *Image) SetVisible(visible bool) {
	i.runOnUI(func() {
		i.widgetBase.setVisible(i, visible)
	})
}

func (i *Image) SetEnabled(enabled bool) {
	i.runOnUI(func() {
		i.widgetBase.setEnabled(i, enabled)
	})
}

func (i *Image) SetScaleMode(mode ImageScaleMode) {
	i.runOnUI(func() {
		if mode == 0 {
			mode = ImageScaleContain
		}
		if i.scaleMode == mode {
			return
		}
		i.scaleMode = mode
		i.invalidate(i)
	})
}

func (i *Image) SetOpacity(alpha byte) {
	i.runOnUI(func() {
		if i.opacity == alpha {
			return
		}
		i.opacity = alpha
		i.invalidate(i)
	})
}

func (i *Image) SetBitmap(bitmap *core.Bitmap) {
	i.runOnUI(func() {
		i.replaceBitmap(bitmap, false)
	})
}

func (i *Image) SetBitmapOwned(bitmap *core.Bitmap) {
	i.runOnUI(func() {
		i.replaceBitmap(bitmap, true)
	})
}

func (i *Image) LoadBytes(data []byte) error {
	img, err := decodeImage(data)
	if err != nil {
		return err
	}
	bitmap, err := bitmapFromImage(img)
	if err != nil {
		return err
	}
	i.SetBitmapOwned(bitmap)
	return nil
}

func (i *Image) NaturalSize() core.Size {
	return i.sourceSize
}

func (i *Image) Bitmap() *core.Bitmap {
	return i.bitmap
}

func (i *Image) OnEvent(Event) bool {
	return false
}

func (i *Image) Paint(ctx *PaintCtx) {
	if !i.Visible() || ctx == nil {
		return
	}
	if i.bitmap == nil {
		return
	}
	_ = ctx.canvas.DrawBitmapAlpha(i.bitmap, i.drawRect(), i.opacity)
}

func (i *Image) Close() error {
	if i.owned && i.bitmap != nil {
		err := i.bitmap.Close()
		i.bitmap = nil
		i.owned = false
		i.sourceSize = core.Size{}
		return err
	}
	i.bitmap = nil
	i.owned = false
	i.sourceSize = core.Size{}
	return nil
}

func (i *Image) replaceBitmap(bitmap *core.Bitmap, owned bool) {
	if i.bitmap == bitmap && i.owned == owned {
		return
	}
	if i.owned && i.bitmap != nil && i.bitmap != bitmap {
		_ = i.bitmap.Close()
	}
	i.bitmap = bitmap
	i.owned = owned
	if bitmap != nil {
		i.sourceSize = core.Size{Width: bitmap.Width, Height: bitmap.Height}
	} else {
		i.sourceSize = core.Size{}
	}
	i.invalidate(i)
}

func (i *Image) drawRect() Rect {
	target := i.Bounds()
	if i.bitmap == nil || target.Empty() {
		return target
	}

	srcW := i.sourceSize.Width
	srcH := i.sourceSize.Height
	if srcW <= 0 || srcH <= 0 {
		return target
	}

	switch i.scaleMode {
	case ImageScaleCenter:
		x := target.X + (target.W-srcW)/2
		y := target.Y + (target.H-srcH)/2
		return Rect{X: x, Y: y, W: srcW, H: srcH}
	case ImageScaleStretch:
		return target
	default:
		width := target.W
		height := target.H
		if width <= 0 || height <= 0 {
			return target
		}
		scaleX := float64(width) / float64(srcW)
		scaleY := float64(height) / float64(srcH)
		scale := scaleX
		if scaleY < scaleX {
			scale = scaleY
		}
		if scale <= 0 {
			scale = 1
		}
		drawW := int32(float64(srcW) * scale)
		drawH := int32(float64(srcH) * scale)
		x := target.X + (target.W-drawW)/2
		y := target.Y + (target.H-drawH)/2
		return Rect{X: x, Y: y, W: drawW, H: drawH}
	}
}

type AnimatedImage struct {
	widgetBase
	frames      []core.AnimatedFrame
	ownedFrames bool
	frameIndex  int
	playing     bool
	opacity     byte
	scaleMode   ImageScaleMode
	timerID     uintptr
}

func NewAnimatedImage(id string) *AnimatedImage {
	return &AnimatedImage{
		widgetBase: newWidgetBase(id, "animated-image"),
		playing:    true,
		opacity:    255,
		scaleMode:  ImageScaleContain,
	}
}

func (a *AnimatedImage) SetBounds(rect Rect) {
	a.runOnUI(func() {
		a.widgetBase.setBounds(a, rect)
	})
}

func (a *AnimatedImage) SetVisible(visible bool) {
	a.runOnUI(func() {
		a.widgetBase.setVisible(a, visible)
		a.syncTimer()
	})
}

func (a *AnimatedImage) SetEnabled(enabled bool) {
	a.runOnUI(func() {
		a.widgetBase.setEnabled(a, enabled)
	})
}

func (a *AnimatedImage) setScene(scene *Scene) {
	oldScene := a.scene()
	if oldScene == scene {
		a.widgetBase.setScene(scene)
		return
	}
	if oldScene != nil && a.timerID != 0 {
		_ = oldScene.stopTimer(a.timerID)
		a.timerID = 0
	}
	a.widgetBase.setScene(scene)
	a.syncTimer()
}

func (a *AnimatedImage) SetScaleMode(mode ImageScaleMode) {
	a.runOnUI(func() {
		if mode == 0 {
			mode = ImageScaleContain
		}
		if a.scaleMode == mode {
			return
		}
		a.scaleMode = mode
		a.invalidate(a)
	})
}

func (a *AnimatedImage) SetOpacity(alpha byte) {
	a.runOnUI(func() {
		if a.opacity == alpha {
			return
		}
		a.opacity = alpha
		a.invalidate(a)
	})
}

func (a *AnimatedImage) SetPlaying(playing bool) {
	a.runOnUI(func() {
		if a.playing == playing {
			return
		}
		a.playing = playing
		a.syncTimer()
	})
}

func (a *AnimatedImage) LoadGIF(data []byte) error {
	frames, err := core.DecodeGIF(data)
	if err != nil {
		return err
	}
	a.SetFramesOwned(frames)
	return nil
}

func (a *AnimatedImage) SetFrames(frames []core.AnimatedFrame) {
	a.runOnUI(func() {
		a.replaceFrames(frames, false)
	})
}

func (a *AnimatedImage) SetFramesOwned(frames []core.AnimatedFrame) {
	a.runOnUI(func() {
		a.replaceFrames(frames, true)
	})
}

func (a *AnimatedImage) NaturalSize() core.Size {
	if len(a.frames) == 0 {
		return core.Size{}
	}
	return core.Size{Width: a.frames[0].Width, Height: a.frames[0].Height}
}

func (a *AnimatedImage) CurrentFrame() int {
	return a.frameIndex
}

func (a *AnimatedImage) OnEvent(evt Event) bool {
	if evt.Type != EventTimer || evt.TimerID != a.timerID || len(a.frames) == 0 {
		return false
	}
	if !a.playing || !a.Visible() {
		return false
	}
	a.frameIndex = (a.frameIndex + 1) % len(a.frames)
	a.invalidate(a)
	a.syncTimer()
	return true
}

func (a *AnimatedImage) Paint(ctx *PaintCtx) {
	if !a.Visible() || ctx == nil || len(a.frames) == 0 {
		return
	}
	frame := a.frames[a.frameIndex%len(a.frames)]
	if frame.Bitmap == nil {
		return
	}
	_ = ctx.canvas.DrawBitmapAlpha(frame.Bitmap, a.drawRect(), a.opacity)
}

func (a *AnimatedImage) Close() error {
	if a.scene() != nil && a.timerID != 0 {
		_ = a.scene().stopTimer(a.timerID)
	}
	a.timerID = 0
	if a.ownedFrames {
		for i := range a.frames {
			if a.frames[i].Bitmap != nil {
				_ = a.frames[i].Bitmap.Close()
			}
		}
	}
	a.frames = nil
	a.ownedFrames = false
	a.frameIndex = 0
	return nil
}

func (a *AnimatedImage) replaceFrames(frames []core.AnimatedFrame, owned bool) {
	if a.ownedFrames {
		for i := range a.frames {
			if a.frames[i].Bitmap != nil {
				_ = a.frames[i].Bitmap.Close()
			}
		}
	}
	a.frames = append(a.frames[:0], frames...)
	a.ownedFrames = owned
	a.frameIndex = 0
	a.invalidate(a)
	a.syncTimer()
}

func (a *AnimatedImage) syncTimer() {
	scene := a.scene()
	if scene == nil {
		return
	}
	if !a.playing || !a.Visible() || len(a.frames) <= 1 {
		if a.timerID != 0 {
			_ = scene.stopTimer(a.timerID)
			a.timerID = 0
		}
		return
	}

	delay := a.frames[a.frameIndex].Delay
	if delay <= 0 {
		delay = 100 * time.Millisecond
	}
	if a.timerID == 0 {
		timerID, err := scene.startTimer(a, 0, delay)
		if err == nil {
			a.timerID = timerID
		}
		return
	}
	_ = scene.updateTimer(a.timerID, delay)
}

func (a *AnimatedImage) drawRect() Rect {
	target := a.Bounds()
	if len(a.frames) == 0 || target.Empty() {
		return target
	}
	frame := a.frames[a.frameIndex%len(a.frames)]
	srcW := frame.Width
	srcH := frame.Height
	if srcW <= 0 || srcH <= 0 {
		return target
	}

	switch a.scaleMode {
	case ImageScaleCenter:
		x := target.X + (target.W-srcW)/2
		y := target.Y + (target.H-srcH)/2
		return Rect{X: x, Y: y, W: srcW, H: srcH}
	case ImageScaleStretch:
		return target
	default:
		scaleX := float64(target.W) / float64(srcW)
		scaleY := float64(target.H) / float64(srcH)
		scale := scaleX
		if scaleY < scaleX {
			scale = scaleY
		}
		if scale <= 0 {
			scale = 1
		}
		drawW := int32(float64(srcW) * scale)
		drawH := int32(float64(srcH) * scale)
		x := target.X + (target.W-drawW)/2
		y := target.Y + (target.H-drawH)/2
		return Rect{X: x, Y: y, W: drawW, H: drawH}
	}
}

func decodeImage(data []byte) (image.Image, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	return img, err
}

func bitmapFromImage(img image.Image) (*core.Bitmap, error) {
	rgba := image.NewRGBA(img.Bounds())
	draw.Draw(rgba, rgba.Bounds(), img, img.Bounds().Min, draw.Src)
	return core.BitmapFromRGBA(rgba)
}
