package web

import (
	"fmt"
	"log"
	"math"
	"net/http"
	"slices"
	"strings"
	"time"

	"sitewatch/internal/report"
	"sitewatch/internal/store"
)

const dayNS = int64(24 * time.Hour)

// uptimeView sind die Anzeigewerte der Erreichbarkeit einer Site (Übersicht und Detailseite).
type uptimeView struct {
	Pct, PctLevel string // Erreichbarkeit im Zeitraum, "" = keine Messung
	Levels        []int  // je Tag 0 ok, 1 Warnung, 2 Ausfall, 3 keine Messung; ältester Tag zuerst
	Latency       string
	State         string // "up", "maint", "down" oder ""
	Off           bool   // für die Site abgeschaltet
}

// pctText schneidet ab statt zu runden: 100 % steht nur da, wo es keinen einzigen Fehlschlag gab.
func pctText(r float64) string {
	return strings.Replace(fmt.Sprintf("%.2f", math.Floor(r*10000)/100), ".", ",", 1) + " %"
}

func ratio(ds []store.DayStat) (float64, bool) {
	var ups, n int
	for _, d := range ds {
		ups, n = ups+d.Ups, n+d.Checks-d.Maint
	}
	if n == 0 {
		return 0, false
	}
	return float64(ups) / float64(n), true
}

// dayLevels bildet die letzten n UTC-Tage (bis heute) auf Stufen ab.
func dayLevels(ds []store.DayStat, now time.Time, n int) []int {
	today := int(now.UTC().UnixNano() / dayNS)
	out := make([]int, n)
	for i := range out {
		out[i] = 3
	}
	for _, d := range ds {
		i := n - 1 - (today - d.Day)
		if i < 0 || i >= n {
			continue
		}
		switch r, ok := d.Ratio(); {
		case !ok:
		case r >= 0.999:
			out[i] = 0
		case r >= 0.99:
			out[i] = 1
		default:
			out[i] = 2
		}
	}
	return out
}

func latencyText(ms int) string {
	switch {
	case ms <= 0:
		return ""
	case ms >= 1000:
		return strings.Replace(fmt.Sprintf("%.1f s", float64(ms)/1000), ".", ",", 1)
	}
	return fmt.Sprintf("%d ms", ms)
}

// uptimeViews liefert die Anzeigewerte für alle Sites; leer, wenn die Prüfung nicht eingerichtet ist.
func (s *Server) uptimeViews(days int) map[string]uptimeView {
	if s.Uptime == nil {
		return nil
	}
	now := s.Now()
	all, err := s.Uptime.UptimeDays(now.AddDate(0, 0, -(days - 1)))
	if err != nil {
		log.Printf("uptime: %v", err)
	}
	med, err := s.Uptime.MedianLatency(now.Add(-time.Hour))
	if err != nil {
		log.Printf("uptime: %v", err)
	}
	sets, err := s.Uptime.UptimeSettings()
	if err != nil {
		log.Printf("uptime: %v", err)
	}
	cfg := s.cfg()
	out := map[string]uptimeView{}
	for id, ds := range all {
		v := uptimeView{Levels: dayLevels(ds, now, days), Latency: latencyText(med[id])}
		if r, ok := ratio(ds); ok {
			v.Pct = pctText(r)
			if int(math.Floor(r*10000)/100) < cfg.UptimeWarnPct {
				v.PctLevel = "warn"
			}
		}
		out[id] = v
	}
	for id, set := range sets {
		if !set.Enabled {
			out[id] = uptimeView{Off: true}
		}
	}
	if cfg.Uptime != nil {
		for id := range out {
			if u, ok := cfg.Uptime.Check(id); ok {
				v := out[id]
				v.State = u.State
				out[id] = v
			}
		}
	}
	return out
}

// uptimeSet speichert Schalter und Intervall einer Site (Formular auf der Detailseite).
func (s *Server) uptimeSet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var iv int
	if _, err := fmt.Sscan(r.FormValue("interval"), &iv); err != nil || !slices.Contains(store.UptimeIntervals, iv) || !report.ValidID(id) {
		http.NotFound(w, r)
		return
	}
	if ids, err := s.siteIDs(); err != nil || !slices.Contains(ids, id) { // nur Sites eines Agenten, keine frei erfundenen IDs
		http.NotFound(w, r)
		return
	}
	if err := s.Uptime.SetUptimeSetting(id, store.UptimeSetting{Enabled: r.FormValue("enabled") == "1", IntervalS: iv}); err != nil {
		log.Printf("uptime: %q: %v", id, err)
		http.Error(w, "interner Fehler", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/sites/"+id, http.StatusSeeOther)
}

type outageView struct {
	From, To string
	Dur      string
	Checks   int
}

func fmtDur(d time.Duration) string {
	if d < time.Minute {
		return "unter 1 Minute"
	}
	return fmt.Sprintf("%d Min.", int(d.Minutes()))
}

// detailUptime sammelt alles für die Karte „Erreichbarkeit“ der Detailseite; nil, wenn die Prüfung nicht eingerichtet ist.
func (s *Server) detailUptime(id string) map[string]any {
	if s.Uptime == nil {
		return nil
	}
	now := s.Now()
	m := map[string]any{"View": s.uptimeViews(90)[id], "Interval": store.DefaultUptime().IntervalS, "Enabled": true, "Intervals": store.UptimeIntervals}
	if sets, err := s.Uptime.UptimeSettings(); err == nil {
		if set, ok := sets[id]; ok {
			m["Interval"], m["Enabled"] = set.IntervalS, set.Enabled
		}
	}
	if all, err := s.Uptime.UptimeDays(now.AddDate(0, 0, -89)); err == nil {
		for _, p := range []struct {
			key  string
			days int
		}{{"P7", 7}, {"P30", 30}, {"P90", 90}} {
			var part []store.DayStat
			for _, d := range all[id] {
				if int(now.UTC().UnixNano()/dayNS)-d.Day < p.days {
					part = append(part, d)
				}
			}
			if r, ok := ratio(part); ok {
				m[p.key] = pctText(r)
			} else {
				m[p.key] = "–"
			}
		}
	}
	if outs, err := s.Uptime.Outages(id, now.AddDate(0, 0, -7)); err == nil {
		var views []outageView
		for _, o := range outs[:min(len(outs), 10)] {
			views = append(views, outageView{fmtTime(o.From), fmtTime(o.To), fmtDur(o.To.Sub(o.From)), o.Checks})
		}
		m["Outages"] = views
	}
	return m
}

func fmtTime(t time.Time) string { return t.Local().Format("02.01. 15:04") }
