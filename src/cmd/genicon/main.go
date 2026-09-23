// Command genicon 生成应用图标（ICON.png / ICON_256.PNG 等），纯标准库无外部依赖。
// 图案：深蓝圆角方块 + 青色"G"环与"W"折线（GateWeaver 编织意象）。
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

var (
	bg     = color.NRGBA{15, 20, 25, 255}
	acc    = color.NRGBA{61, 169, 252, 255}
	accDim = color.NRGBA{32, 92, 138, 255}
)

func main() {
	out := "dist"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		panic(err)
	}
	for _, spec := range []struct {
		name string
		size int
	}{{"ICON.png", 64}, {"ICON_256.PNG", 256}, {"ICON_64.PNG", 64}, {"ICON_128.PNG", 128}} {
		f, err := os.Create(out + "/" + spec.name)
		if err != nil {
			panic(err)
		}
		img := render(spec.size)
		if err := png.Encode(f, img); err != nil {
			panic(err)
		}
		_ = f.Close()
		fmt.Println("wrote", out+"/"+spec.name)
	}
}

func render(size int) image.Image {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	s := float64(size)
	radius := 0.18 * s
	stroke := math.Max(2, 0.055*s)
	cx, cy := 0.5*s, 0.5*s

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			fx, fy := float64(x)+0.5, float64(y)+0.5
			// 圆角方块背景（含 1px 抗锯齿边）
			if !inRoundedRect(fx, fy, s, radius) {
				continue
			}
			col := bg
			d := color.NRGBA{0, 0, 0, 0}
			// G：开口环（留 60° 缺口朝右）
			r := 0.28 * s
			dx, dy := fx-cx+0.04*s, fy-cy
			rr := math.Hypot(dx, dy)
			angle := math.Atan2(dy, dx)
			onRing := math.Abs(rr-r) <= stroke/2
			inGap := angle > -0.55 && angle < 0.55 // 右侧缺口
			if onRing && !inGap {
				d = acc
			}
			// G 的横杠（缺口下沿向内）
			if fy > cy-0.02*s && fy < cy+stroke && fx > cx+0.08*s && fx < cx+0.30*s {
				d = acc
			}
			// W：四条折线段
			pts := [][2]float64{
				{0.22, 0.62}, {0.38, 0.82}, {0.50, 0.45}, {0.62, 0.82}, {0.78, 0.62},
			}
			for i := 0; i < len(pts)-1; i++ {
				p1 := [2]float64{pts[i][0] * s, pts[i][1] * s}
				p2 := [2]float64{pts[i+1][0] * s, pts[i+1][1] * s}
				if distToSeg(fx, fy, p1, p2) <= stroke/2 {
					d = accDim
				}
			}
			col = blend(col, d)
			img.SetNRGBA(x, y, col)
		}
	}
	return img
}

func inRoundedRect(x, y, s, r float64) bool {
	if x < 0 || y < 0 || x > s || y > s {
		return false
	}
	cx, cy := x, y
	if x < r {
		cx = r
	} else if x > s-r {
		cx = s - r
	}
	if y < r {
		cy = r
	} else if y > s-r {
		cy = s - r
	}
	return math.Hypot(x-cx, y-cy) <= r
}

func distToSeg(px, py float64, a, b [2]float64) float64 {
	ax, ay, bx, by := a[0], a[1], b[0], b[1]
	dx, dy := bx-ax, by-ay
	t := ((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy + 1e-9)
	if t < 0 {
		t = 0
	}
	if t > 1 {
		t = 1
	}
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

func blend(base, over color.NRGBA) color.NRGBA {
	if over.A == 0 {
		return base
	}
	return over
}
