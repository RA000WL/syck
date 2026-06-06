package progress

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/schollz/progressbar/v3"
)

type Bar struct {
	pb       *progressbar.ProgressBar
	w        io.Writer
	findings atomic.Int64
	count    atomic.Int64
	start    time.Time
}

func New(w io.Writer) *Bar {
	return NewWithTotal(w, -1)
}

func NewWithTotal(w io.Writer, total int) *Bar {
	desc := "scanning"
	if total > 0 {
		desc = fmt.Sprintf("scanning (%d files)", total)
	}
	opts := []progressbar.Option{
		progressbar.OptionSetWriter(w),
		progressbar.OptionSetDescription(desc),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionUseANSICodes(true),
	}
	if total > 0 {
		opts = append(opts, progressbar.OptionSetWidth(40))
	}
	return &Bar{
		pb:    progressbar.NewOptions(total, opts...),
		w:     w,
		start: time.Now(),
	}
}

// Tick is the callback installed into scanner.Config.Progress. It advances
// the bar by the file delta and reflects the latest finding count.
func (b *Bar) Tick(filesScanned, findings int) {
	cur := int64(filesScanned)
	prev := b.count.Load()
	if delta := cur - prev; delta > 0 {
		_ = b.pb.Add64(delta)
		b.count.Store(cur)
	}
	b.findings.Store(int64(findings))
}

func (b *Bar) Add(n int) {
	_ = b.pb.Add(n)
	b.count.Add(int64(n))
}

func (b *Bar) Finish() {
	_ = b.pb.Finish()
	elapsed := time.Since(b.start).Round(time.Millisecond)
	_, _ = fmt.Fprintf(b.w, "\nscanned %d files in %s (%d findings)\n",
		b.count.Load(), elapsed, b.findings.Load())
}
